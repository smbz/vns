#!/usr/bin/env python

"""This differs from topo_interactor.py in that it doesn't require twisted, and
uses the python socket API instead.  This makes it rather easier to distribute."""

import sys
import socket
from threading import Thread, Event, Lock
import hashlib
import readline
import Queue
import struct
import time
from optparse import OptionParser

DEFAULT_PORT = 12346
HISTORY_FILE = ".ti2_history"

def debug(msg):
    """Prints out a debugging message"""
    return
    print msg


def main():
    
    # Parse the command line
    parser = OptionParser()
    parser.add_option("-a", "--auth-key", dest="auth_key",
                      default="auth_key", help="File containing the VNS auth "
                      "key")
    parser.add_option("-p", "--port", default=DEFAULT_PORT,
                      help="Remote port on VNS server to connect to")
    parser.add_option("-s", "--server", default="vns-1",
                      help="VNS server to connect to")
    parser.add_option("-t", "--topology", default=-1,
                      help="Topology number to connect to")
    parser.add_option("-u", "--username",
                      help="Username on the VNS server")
    (options, args) = parser.parse_args(sys.argv)

    # Check that we have a valid topology number
    if options.topology == -1:
        parser.error("no topology number specified (with -t)")
    try:
        tid = int(options.topology)
    except ValueError:
        parser.error("the topology number must be an integer")
    if tid < 0:
        parser.error("the topology number cannot be negative")

    # Check we have a username
    if options.username is None:
        parser.error("no username specified (with -u)")

    # Get the auth key from the specified file
    try:
        with open(options.auth_key, "rb") as f:
            auth_key = f.read()
    except IOError as e:
        parser.error("Cannot read auth key from %s: %s" % (options.auth_key, e))

    # Make the port number into an integer and check it's valid
    try:
        port = int(options.port)
    except ValueError:
        parser.error("expecting an integer port number; got %s" % options.port)
    if port < 1 or port > 65535:
        parser.error("expected a port number from 1 to 65535, not %d" % port)

    # Connect to the VNS server
    try:
        skt = socket.create_connection((options.server, options.port))
    except socket.error as e:
        parser.error("Cannot connect to %s:%d: %s" % (options.server,
                                                      port,
                                                      e))
    client = TopoInteractor(skt, options.username, auth_key, tid)


class TopoInteractor(object):

    def __init__(self, skt, username, auth_key, topo_id):
        """Constructor.  Initialise a TIClient on the specified socket.
        @param skt  A socket which has been connected to the VNS server
        @param username  The username with which to authenticate with the server
        @param auth_key  The auth key with which to authenticate with the server
        @param toppo_id  The ID of the topology to connect to
        """
        self.skt = skt
        self.username = username
        self.auth_key = auth_key
        self.topo_id = topo_id

        # Start a client to listen for messages from the server
        self.client = TIClient(skt,
                               conn_lost=self.conn_lost,
                               recv_pkt=self.recv_pkt)

        # Create a dictionary mapping commands to their callbacks
        cmds = {"tap": self.cli_tap,
                "help": self.cli_help,
                "exit": self.cli_exit,
                "\x04": self.cli_exit}

        # Start a command line to interact with the user
        self.cli = CommandLine(cmds, history_file=HISTORY_FILE)

        # Create a dictionary mapping node names to dictionaries mapping
        # interface names to Tap objects
        self.tap_lock = Lock()
        self.taps = {}


    def conn_lost(self):
        """Called when the connection to the server is lost."""
        debug("conn_lost")
        
        # Print out a message saying we've lost the connection
        self.cli.prt("Connection to VNS server lost")

        # Tell the command line to terminate and wait until it has
        self.cli.stop()

    def recv_pkt(self, typ, pkt):
        """Called when a packet is received from the connection
        @param type  The type of the packet
        @param pkt  The payload of the packet"""

        debug("Handling packet type %d" % typ)

        if typ == AuthRequest.typ:
            self.handle_auth_request(pkt)
        elif typ == AuthStatus.typ:
            self.handle_auth_status(pkt)
        elif typ == TIPacket.typ:
            self.handle_packet(pkt)
        elif typ == BadNodeOrPort.typ:
            self.handle_bad_node_or_port(pkt)
        elif typ == Banner.typ:
            self.handle_banner(pkt)
        else:
            self.cli.prt("Received unknown packet type from server: %d" % typ)

    def handle_auth_request(self, pkt):
        """Handles an auth request packet from the server by sending back an
        auth reply.
        @param pkt  The received packet, with length and type headers"""
        debug("Handling auth request")
        
        # Get the salt from the packet
        try:
            salt = AuthRequest.unpack(pkt).salt
        except ValueError:    
            self.cli.prt("Received invalid auth request packet from server")
            return

        # We need to concatenate the salt and auth key together, then hash; this
        # is then sent to the VNS server for authentication
        sha = hashlib.sha1(salt + self.auth_key)
        debug("Sending auth reply for user %s" % self.username)
        self.client.send(AuthReply(self.username, sha.digest()).pack())

    def handle_auth_status(self, pkt):
        """Handles an auth status packet from the server, telling us the status
        of out authentication."""
        
        # Decode the packet
        try:
            pkt = AuthStatus.unpack(pkt)
        except ValueError:
            self.cli.prt("Received invalid auth status packet from server")
            return

        # Print the messages
        if pkt.auth_ok:
            self.cli.prt("Successfully authenticated")

            # Successfully authenticated, can open the topology
            self.client.send(TIOpen(self.topo_id).pack())
        else:
            self.cli.prt("Authentication failed")
        self.cli.prt(pkt.msg)

    def handle_packet(self, pkt):
        """Handles a message from the server containing a packet, possibly to
        be logged.
        @param pkt  The received packet, without length or type headers"""

        debug("Handling packet packet")

        # Decode the packet
        try:
            pkt = TIPacket.unpack(pkt)
        except ValueError:
            self.cli.prt("Received invalid 'packet received' packet from server")
            return

        # See if we have any taps running on this node
        self.tap_lock.acquire()
        try:
            debug(self.taps)
            intfs = self.taps[pkt.node]
        except KeyError:
            # We have no taps running on this node; drop the packet
            debug("Got tapped packet for unknown node '%s'" % pkt.node)
            return
        finally:
            self.tap_lock.release()

        # Get the tap object for the interface
        self.tap_lock.acquire()
        try:
            tap = intfs[pkt.intf]
        except KeyError:
            # We have no taps running for this interface on this node; drop
            debug("Got tapped for unknown interface '%s' on node '%s'" % (pkt.node, pkt.intf))
            return
        finally:
            self.tap_lock.release()

        # Send the packet to the Tap
        debug("Giving packet to tap")
        tap.handle_packet(pkt.ethernet_frame)

    def handle_bad_node_or_port(self, pkt):
        """Handles a "bad node or port" error message from the server, which
        is sent when trying to set a tap on an invalid node"""
        
        # Decode the packet
        try:
            pkt = BadNodeOrPort.unpack(pkt)
        except ValueError:
            self.cli.prt("Received invalid 'bad node or port' packet from server")
            return

        # Print the error message
        if pkt.code == BadNodeOrPort.BAD_NODE:
            self.cli.prt("No such node: %s" % pkt.node)
        elif pkt.code == BadNodeOrPort.BAD_INTF:
            self.cli.prt("No such interface on %s: %s" % (pkt.node, pkt.intf))
        else:
            self.cli.prt("Unrecognised code in bad node/port message: %d" % pkt.code)

        # Remove the node/port combo from our list of taps
        self.tap_lock.acquire()
        try:
            self.taps[pkt.node][pkt.intf].finalise()
            del self.taps[pkt.node][pkt.intf]
        except KeyError:
            pass
        finally:
            self.tap_lock.release()

    def handle_banner(self, pkt):
        """Handles a banner packet from the server, i.e. one containing a
        message to be printed."""

        # Decode the packet
        try:
            pkt = Banner.unpack(pkt)
        except ValueError:
            self.cli.prt("Bad banner message from server")
            return
        
        # Print the message
        self.cli.prt(pkt.msg)

    def cli_tap(self, argv):

        def help():
            self.cli.prt("Sets a tap on a node.  Usage: tap <node>:<interface> off|<output>\n"
                         "If <output> is a single hyphen (\"-\"), output to the screen; "
                         "otherwise outputs in pcap format to the file of name <output>.")

        # If the 2nd arg is help, print usage info
        if len(argv) == 2 and argv[1] == "help":
            help()
            return

        # Check we have the right nr args
        if len(argv) != 3:
            self.cli.prt("Expected 3 arguments")
            help()
            return

        # Get the node and interface names
        ni = argv[1].strip().split(':')
        try:
            node = ni[0]
            intf = ni[1]
        except IndexError:
            help()
            return

        # If the 3rd argument is "off", then turn off the tap
        if argv[2] == 'off':
            self.client.send(TITap(node, intf, False).pack())
            try:
                del self.taps[node][intf]
            except KeyError:
                pass
            return

        # Create and send a tap request packet to the server
        pkt = TITap(node, intf, True)
        self.client.send(pkt.pack())

        # Create a Tap object
        if argv[2] == '-':
            tap = ScreenTap()
        else:
            tap = PcapTap(argv[2])

        # Add the Tap object to our list of taps
        self.tap_lock.acquire()
        try:
            _ = self.taps[node]
        except KeyError:
            self.taps[node] = {}
        self.taps[node][intf] = tap
        debug(self.taps)
        self.tap_lock.release()


    def cli_help(self, argv):
        """Responds to a 'help' command by printing a list of commands and what
        they do."""
        self.cli.prt("Available commands:\n"
                     "help: shows this help\n"
                     "tap:  logs packets going into a node\n"
                     "exit: quits the topology interactor\n"
                     "For more help on a command, type '<command> help'.")
        return

    def cli_exit(self, argv):
        """Responds to an 'exit' command by shutting down."""
        
        # First, remove all taps
        for (node, intfs) in self.taps.iteritems():
            for (intf, tap) in intfs.iteritems():
                self.client.send(TITap(node, intf, False).pack())

        # Now close the connection
        self.client.stop()

        # And shut down the CLI
        self.cli.stop()


class Tap(object):
    """An object which represents a tap on an interface.  This class doesn't 
    do anything; for that, you need ScreenTap or PcapTap.  There's no particular
    need to have this class given the python type system, but it makes the code
    easier to understand."""
    
    def handle_packet(self, pkt):
        pass

    def finalise(self):
        pass


class ScreenTap(Tap):
    """A Tap which prints received packets to the screen."""

    @staticmethod
    def _print(msg):
        """A wrapper around print because the python print statement is not
        callable"""
        print msg

    def __init__(self, printer=None):
        """Constructor.  Creates a new Tap that will print human-readable
        versions of packets received using printer, or to stdout if printer is
        not specified.
        @param printer  A callable which takes a single string argument, and
        (hopefully) prints it somewhere.  By default, uses the python print
        statement."""
        if printer is None: printer = self._print
        setattr(self, "prt", staticmethod(printer))

    def handle_packet(self, pkt):
        """Prints a human-readable version of an ethernet packet using the
        printer specified in the constructor.
        @param pkt  The ethernet frame to print, including ethernet headers
        (destination and source MACs and ethertype) but not the CRC."""

        # Format the packet and make it human-readable, then print it
        formatted_pkt = str(PacketDecoder(pkt))
        prt = getattr(self, "prt")
        prt.__get__(None, ScreenTap)(formatted_pkt + "\n")


class PcapTap(Tap):
    """A Tap which writes packets out to a pcap file"""

    # Constants for the pcap file
    MAGIC_NUMBER = 0xa1b2c3d4
    VERSION_MAJOR = 2
    VERSION_MINOR = 4
    TYPE_ETHERNET = 1

    def __init__(self, filename):
        """Constructor.  Initialises a new Tap that will write any packets
        received to the file specified by filename in pcap format."""

        # Open the file for writing
        self.file = open(filename, "wb")

        # Create and write the pcap global header
        hdr = struct.pack("! I 2H i 3I",
                          self.MAGIC_NUMBER,
                          self.VERSION_MAJOR,
                          self.VERSION_MINOR,
                          0, # GMT correction
                          0, # timestamp accuracy
                          0xffff, # maximum packet length
                          self.TYPE_ETHERNET)
        self.file.write(hdr)

    def handle_packet(self, pkt):
        """Writes an ethernet packet to the pcap file.
        @param pkt  The packet to write, including ethernet src, dst and type
        but not including the CReC"""
        
        # Create and write the pcap packet header and packet
        t = time.time()
        sec = int(t)
        usec = (t - sec) * 1e6
        hdr = struct.pack("!4I",
                          sec,
                          usec,
                          len(pkt),
                          len(pkt))
        self.file.write(hdr)
        self.file.write(pkt)

    def finalise():
        """Finalises the tap by closing the output file."""
        self.file.close()


def verify_ip_checksum(header):
    """Verifies that an IP checksum is correct.  Returns True if it is valid,
    False if it is not.  The header pass should include the checksum as it was
    received.
    @param header  The IP (or ICMP) header to verify the checksum for, including
    the checksum as it was received."""
    if len(header) % 2 != 0:
        raise ValueError("The header length should be a multiple of 2 octets")
    
    # Calculate the 1's complement sum of everything in the header
    total = 0
    for i in range (0, len(header), 2):
        (x,) = struct.unpack_from("!H", header, i)
        total += x
    total = (total & 0xffff) + ((total >> 16) & 0xffff)

    return total == 0xffff


class MACAddress(object):
    """Object representing a MAC address"""

    def __init__(self, mac):
        if len(mac) != 6:
            raise ValueError("MAC address of wrong length")

        self.mac = mac

    def __str__(self):
        return '-'.join(["%02x" % ord(c) for c in self.mac])


class IPv4Address(object):
    """Object representing an IPv4 address"""

    def __init__(self, ip):
        """Constructor.  Initialise an IP from a string.  If the string is 4
        bytes long, it is taken to be a binary IP; otherwise, a dotted decimal
        IP."""
        if len(ip) == 4:
            self.ip = ip
        else:
            self.ip = socket.inet_aton(ip)

    def __str__(self):
        return '.'.join([str(ord(c)) for c in self.ip])


class Layer(object):
    """An object representing a network layer."""

    def __init__(self, data):
        """Initialise a new layer with the given data.  The data includes the
        data for the given layer as well as any sub-layers."""
        self.data = data
    
    def __str__(self):
        """By default, we just do a hex dump of the data"""
        return hexdump(self.data)


class EthernetLayer(Layer):
    """An object representing an ethernet frame"""

    def __init__(self, data):
        
        # Check that the frame is long enough
        if len(data) < 14:
            raise valueError("Packet is too short to be a valid ethernet frame")
        
        # Decode the dst/src addresses and ethertype
        self.dst_mac = MACAddress(data[:6])
        self.src_mac = MACAddress(data[6:12])
        (self.ethertype,) = struct.unpack("!H", data[12:14])

        # Decode any sub-layers
        try:
            if self.ethertype == 0x0800:
                self.sub = IPv4Layer(data[14:])
            elif self.ethertype == 0x0806:
                self.sub = ARPLayer(data[14:])
            else:
                self.sub = Layer(data[14:])
        except ValueError:
            self.sub = Layer(data[14:])

    def __str__(self):
        """Returns a human-readable string representing this packet and layer"""
        
        # Make a string for the ethernet type
        if self.ethertype == 0x0800:
            ethertype = "IPv4 (0x0800)"
        elif self.ethertype == 0x0806:
            ethertype = "ARP (0x0806)"
        else:
            ethertype = "0x%04x" % self.ethertype

        # Make a string for the packet, including sub-layers
        ret = "Eth  dst: %s  src: %s  type: %s\n%s" % (self.dst_mac,
                                                            self.src_mac,
                                                            ethertype,
                                                            self.sub)
        return ret


class IPv4Layer(Layer):

    def __init__(self, data):
        
        # Check that the packet is long enough
        if len(data) < 20:
            raise ValueError("Packet is not long enough to be a valid IP packet")

        # Check that the packet has the right version and length
        if (ord(data[0]) & 0xf0) >> 4 != 4:
            raise ValueError("Version for IPv4 packet is not 4")
        if (ord(data[0]) & 0x0f) != 5:
            raise ValueError("Header is wrong length for IPv4 packet")

        # Unpack the destination and source addresses, TTL and protocol number
        self.src = IPv4Address(data[12:16])
        self.dst = IPv4Address(data[16:20])
        (self.ttl, self.proto) = struct.unpack("! 2B", data[8:10])

        # Verify that the checksum is good
        if not verify_ip_checksum(data[:20]):
            raise ValueError("Invalid IP checksum")

        # Decode any sub-layers
        try:
            if self.proto == 0x01:
                self.sub = ICMPLayer(data[20:])
            elif self.proto == 0x04:
                self.sub = IPLayer(data[20:])
            elif self.proto == 0x06:
                self.sub = TCPLayer(data[20:])
            elif self.proto == 0x11:
                self.sub = UDPLayer(data[20:])
            else:
                self.sub = Layer(data[20:])
        except ValueError:
            self.sub = Layer(data[20:])

    def __str__(self):

        # Make a string for the protocol number
        if self.proto == 0x01:
            proto = "ICMP (0x01)"
        elif self.proto == 0x04:
            proto = "encapsulated IP (0x04)"
        elif self.proto == 0x06:
            proto = "TCP (0x06)"
        elif self.proto == 0x11:
            proto = "UDP (0x11)"
        else:
            proto = "0x%x" % self.proto
        
        return "IPv4 dst: %s  src: %s  ttl: %d  proto: %s\n%s" % (self.dst,
                                                                  self.src,
                                                                  self.ttl,
                                                                  proto,
                                                                  self.sub)

ICMP_TYPES = {0x00: 'echo reply',
              0x03: 'dest unreachable',
              0x04: 'source quench',
              0x05: 'redirect message',
              0x06: 'alternate host address',
              0x08: 'echo request',
              0x09: 'router advertisement',
              0x0a: 'router solicitation',
              0x0b: 'time exceeded'}

ICMP_DEST_UNREACH_CODES = {0x00: 'network unreachable',
                           0x01: 'host unreacable',
                           0x02: 'protocol unreacable',
                           0x03: 'port unreachable',
                           0x04: 'fragmentation needed but don\'t fragment bit set',
                           0x05: 'source route failed',
                           0x06: 'destination network unknown',
                           0x07: 'destination host unknown',
                           0x08: 'source host isolated',
                           0x09: 'destination network administratively prohibited',
                           0x0a: 'destination host administratively prohibited',
                           0x0b: 'network unreachable for TOS',
                           0x0c: 'host unreachable for TOS',
                           0x0d: 'communication administratively prohibited by filtering',
                           0x0e: 'host precedence violation',
                           0x0f: 'precedence cutoff in effect'}

class ICMPLayer(Layer):
    
    def __init__(self, data):
        
        # Check the packet is not too short
        if len(data) < 8:
            raise ValueError("Too short to be valid ICMP message")

        # Unpack the header
        (self.type, self.code) = struct.unpack_from("! 2B", data)

        # Verify the checksum
        if not verify_ip_checksum(data):
            raise ValueError("Invalid checksum")

        try:
            if (self.type == 8 or self.type == 0) and self.code == 0:
                # Should be a ping packet
                self.sub = ICMPEchoLayer(data[4:])
            elif len(data) > 8 and ord(data[8]) == 0x45:
                # Might be an IPv4 packet
                self.sub = IPv4Layer(data[8:])
            else:
                self.sub = Layer(data[8:])
        except ValueError:
            self.sub = Layer(data[8:])

    def __str__(self):
        
        # Make a string for the ICMP type
        try:
            t = ICMP_TYPES[self.type]
        except KeyError:
            t = "type: 0x%x" % self.type

        # Make a string for the ICMP code
        try:
            if self.code == 0x03:
                c = ICMP_DEST_UNREACH_CODES[self.code]
            else:
                c = "code: 0x%x" % self.code
        except KeyError:
            c = "code: 0x%x" % self.code

        # Return a complete string
        return "ICMP %s (%s)\n%s" % (t, c, self.sub)


TCP_FLAGS = {0x01: 'FIN',
             0x02: 'SYN',
             0x04: 'RST',
             0x08: 'PSH',
             0x10: 'ACK',
             0x20: 'URG'}

TCP_FLAGS_REV = {'FIN': 0x01,
                 'SYN': 0x02,
                 'RST': 0x04,
                 'PSH': 0x08,
                 'ACK': 0x10,
                 'URG': 0x20}

class ICMPEchoLayer(Layer):

    def __init__(self, data):

        # Check the data are long enough
        if len(data) < 4:
            raise ValueError("Too short to be echo request part of ICMP packet")

        (self.ident,
         self.seq) = struct.unpack_from("!2H", data)

        self.sub = Layer(data[4:])

    def __str__(self):
        return "     sequence number %d, ident number %d\n%s" % (self.seq, self.ident, self.sub)

class TCPLayer(Layer):
    
    def __init__(self, data):
        
        # Check the data is long enough to be a TCP packet
        if len(data) < 20:
            raise ValueError("Packet is too short to be a valid TCP packet")

        # Get the ports and seq and ack numbers
        (self.src_port,
         self.dst_port,
         self.seq_num,
         self.ack_num) = struct.unpack_from("! 2H 2I", data)

        # Check that the header length is as expected
        hdr_len = (ord(data[12]) & 0xf0) >> 4
        if hdr_len < 5:
            raise ValueError("TCP header length is too short (header length %d octets, data %d octets)"
                             % (hdr_len*4, len(data)))
        if hdr_len*4 > len(data):
            raise ValueError("TCP packet is too short for given header length (header length %d octets, data %d octets)"
                             % (hdr_len*4, len(data)))
        elif hdr_len == 5:
            self.options = ''
        else:
            self.options = data[20:4*hdr_len]

        # Get the flags
        self.flags = ord(data[13]) & 0x3f

        # We don't expect anything else easily decodable in a TCP packet
        self.sub = Layer(data[4*hdr_len:])

    def __str__(self):
        
        # Convert the flags to a string
        flags = []
        for (flag,name) in TCP_FLAGS.iteritems():
            if self.flags & flag != 0:
                flags.append(name)
        flags = ','.join(flags)

        # Get a hexdump of any TCP options
        if len(self.options) > 0:
            options = "     options:\n%s" % hexdump(self.options)
        else:
            options = ""
        
        # Get the sequence and ack numbers if necessary
        seq = "     sequence number:  %d\n" % self.seq_num
        if self.flags & TCP_FLAGS_REV['ACK'] != 0:
            ack = "     ack number:  %d\n" % self.ack_num
        else:
            ack = ''

        return "TCP  %s dst_port: %d  src_port: %d\n%s%s%s%s" % (
            flags,
            self.dst_port,
            self.src_port,
            seq, ack,
            options,
            self.sub)


class UDPLayer(Layer):

    def __init__(self, data):
        
        # Make sure the data are long enough
        if len(data) < 8:
            raise ValueError("Packet is too short to be UDP")
        
        # Decode the port numbers
        (self.src_port,
         self.dst_port) = struct.unpack_from("!2H", data)

        self.sub = Layer(data[8:])

    def __str__(self):
        return "UDP  dst_port: %d  src_port: %d\n%s" % (
            self.dst_port, self.src_port, self.sub)


class ARPLayer(Layer):

    def __init__(self, data):

        # Make sure the data are long enough
        if len(data) < 8:
            raise ValueError("Too short to be an ARP frame")

        # Get the ARP header
        (self.htype,
         self.ptype,
         self.hlen,
         self.plen,
         self.oper) = struct.unpack_from("! 2H 2B H", data)

        # Get the hardware and protocol addresses
        if len(data) != 8 + 2*self.hlen + 2*self.plen:
            raise ValueError("ARP frame is wrong length to contain HW & prot. "
                             "addresses of specified length")

        if self.hlen == 6 and self.htype == 1:
            self.sha = MACAddress(data[8:14])
            self.tha = MACAddress(data[18:24])
        else:
            self.sha = ' '.join(["%02x" % ord(c) for c in data[8:8+hlen]])
            self.tha = ' '.join(["%02x" % ord(c) for c in data[8+hlen+plen:8+2*hlen+plen]])
        if self.plen == 4 and self.ptype == 0x0800:
            self.spa = IPv4Address(data[14:18])
            self.tpa = IPv4Address(data[24:28])
        else:
            self.spa = ' '.join(["%02x" % ord(c) for c in data[8+hlen:8+hlen+plen]])
            self.tpa = ' '.join(["%02x" % ord(c) for c in data[8+2*hlen+plen:8+2*hlen+plen]])

    def __str__(self):
        
        # Make a string for the operation
        if self.oper == 1:
            oper = "request"
        elif self.oper == 2:
            oper = "reply"
        else:
            oper = "unknown opcode (%d)" % self.oper

        # Make a string for the hardware and protocol types and lengths
        if self.htype == 1 and self.hlen == 6:
            hw = "ethernet"
        else:
            hw = "hw: %d (len %d)" % (self.htype, self.hlen)
        if self.ptype == 0x0800 and self.plen == 4:
            prot = "IPv4"
        else:
            prot = "prot: 0x%04x (len %d)" % (self.ptype, self.plen)

        return ("ARP  %s %s / %s  src: (%s,%s)\n"
                "     dst: (%s,%s)" % (oper, hw, prot,
                                       self.sha,
                                       self.spa,
                                       self.tha,
                                       self.tpa))

class PacketDecoder(object):
    """A decoder for ethernet frames"""
    
    def __init__(self, frame):
        """Constructor.  Takes a raw ethernet frame and decodes it.
        @param frame  The ethernet frame to decode, starting with destination
        and source MAC addresses."""
        self.layer = EthernetLayer(frame)

    def __str__(self):
        return str(self.layer)


class Packet(object):

    @classmethod
    def unpack(cls, data):
        # Unpack the data
        unpacked = struct.unpack_from(cls.FORMAT, data)

        # Get the length and type fields
        try:
            l = unpacked[0]
            t = unpacked[1]
        except IndexError:
            raise ValueError("The format for %s does not have length and type fields" % cls)

        # Check the length and type fields
        if l != len(data):
            raise ValueError("Length in header does not match length of packet")
        if t != cls.typ:
            raise ValueError("Wrong type packet for method called")

        # Generate a list of the fields
        fields = list(unpacked[2:])

        # See if there is anything after the struct
        fmt_size = struct.calcsize(cls.FORMAT)
        if len(data) > struct.calcsize(cls.FORMAT):
            fields.append(data[fmt_size:])

        # Call a constructor for a subclass with the unused fields we've unpacked
        try:
            return cls(*fields)
        except TypeError:
            raise ValueError("Was not expecting additional arguments for %s" % cls)


class Banner(Packet):
    """A banner packet from the server"""
    
    typ = 5
    FORMAT = "! 2H"

    def __init__(self, msg):
        self.msg = msg

    def pack(self):
        length = struct.calcsize(self.FORMAT)
        return struct.pack(self.FORMAT, length, self.typ, msg)


class AuthRequest(Packet):
    
    typ = 128
    FORMAT = "!2H"

    def __init__(self, salt):
        self.salt = salt

    def pack(self):
        length = struct.calcsize(self.FORMAT) + len(salt)
        return struct.pack(self.FORMAT, length, self.typ) + self.salt


class AuthReply(Packet):
    
    typ = 256
    FORMAT = "!2HI"

    def __init__(self, username, sha):
        self.username = username
        self.sha = sha

    def pack(self):
        length = struct.calcsize(self.FORMAT) + len(self.username) + len(self.sha)
        return struct.pack(self.FORMAT, length, self.typ, len(self.username)) + self.username + self.sha


class AuthStatus(Packet):

    typ = 512
    FORMAT = "!2HB"

    def __init__(self, auth_ok, msg):
        self.auth_ok = auth_ok
        self.msg = msg

    def pack(self):
        length = struct.calcsize(self.FORMAT) + len(self.msg)
        return struct.pack(self.FORMAT, length, self.typ, self.auth_ok, self.msg)


class BadNodeOrPort(Packet):
    
    typ = 7
    FORMAT="! 2H 30s 5s I"

    def __init__(self, node, intf, code):
        self.node = node.rstrip("\x00")
        self.intf = intf.rstrip("\x00")
        self.code = code

    def pack(self):
        length = struct.calcsize(self.FORMAT)
        return struct.pack(self.FORMAT, length, self.typ, self.node, self.intf, self.code)


class TITap(Packet):

    typ = 3
    FORMAT = "! 2H 30s 5s 3b"

    def __init__(self, node, intf, tap, consume=0, ip_only=0, bidirectional=True):
        self.node = node.rstrip("\x00")
        self.intf = intf.rstrip("\x00")
        self.tap = tap != 0
        self.consume = consume != 0
        self.ip_only = (ip_only & 1) != 0
        self.bidirectional = (ip_only & 2) != 0 or bidirectional

    def pack(self):
        length = struct.calcsize(self.FORMAT)
        return struct.pack(self.FORMAT, length, self.typ, self.node, self.intf,
                           1 if self.tap else 0, 1 if self.consume else 0,
                           (1 if self.ip_only else 0) | (2 if self.bidirectional else 0))


class TIPacket(Packet):

    typ = 2
    FORMAT = "! 2H 30s 5s"

    def __init__(self, node, intf, ethernet_frame):
        self.node = node.rstrip("\x00")
        self.intf = intf.rstrip("\x00")
        self.ethernet_frame = ethernet_frame

    def pack(self):
        length = struct.calcsize(self.FORMAT)
        return struct.pack(self.FORMAT, length, self.typ, self.node, self.intf, self.ethernet_frame)


class TIOpen(Packet):

    typ = 1
    FORMAT = "!3H"

    def __init__(self, tid):
        self.tid = tid

    def pack(self):
        length = struct.calcsize(self.FORMAT)
        return struct.pack(self.FORMAT, length, self.typ, self.tid)


class CommandLine(object):
    """Implements a command-line interface on stdout/stdin."""

    def __init__(self, commands, default=None, prompt=">>> ", history_file=None):
        """Constructor.  Sets up a command-line interface with the given
        commands.
        @param commands  A dictionary mapping commands to callables.  When a
        command is issued by the user, the corresponding callable is called.
        The callable is given a single argument, which is a list of arguments
        on the command line.  The first item in the list is the name by which
        the callable was invoked, in the same manner as sys.argv.  All callbacks
        are guaranteed to be called from the same thread, but this will not be
        the same thread that called this constructor.
        @param default  If a command issued by the user is not found in the
        commands dictionary, the default callable is called instead.
        @param prompt  The prompt at which the user types commands."""
        self.commands = commands
        self.default = default
        self.prompt = prompt
        self.history_file = history_file

        # Load the history file
        if history_file:
            try:
                readline.read_history_file(history_file)
            except IOError:
                # Probably the file doesn't exist
                pass

        # Create a queue of messages to be printed
        self.print_queue = Queue.Queue()

        # Create a thread to monitor the command line and call the relevant
        # callback when a command is issued
        self.printer_thread = Thread(target=self._run_printer, name="CL_printer")
        self.caller_thread = Thread(target=self._run_caller, name="CL_caller")

        # Create events and locks needed to keep the threads synchronised
        self.command_lock = Lock()
        self.print_event = Event()
        self.print_terminate = Event()
        self.caller_terminate = Event()

        # A lock to prevent multiple things printing at the same time
        self.output_lock = Lock()

        # A lock to prevent multiple threads calling readline methods at the
        # same time - might not be necessary, the documentation isn't explicit
        self.readline_lock = Lock()

        # Start the necessary threads
        self.printer_thread.start()
        self.caller_thread.start()


    def stop(self):
        self.print_terminate.set()
        self.caller_terminate.set()
        self.print_event.set()

        # Save the history
        if self.history_file:
            readline.write_history_file(self.history_file)


    def prt(self, msg):
        """Put a message in the queue to be printed and poke the printer
        thread to print it"""
        self.print_queue.put(msg)
        self.print_event.set()
        

    def _run_printer(self):
        """A thread to print messages to the command line."""
        
        while(True):
            
            # See if we have anything to print
            loop = True
            printed = False
            
            self.output_lock.acquire()
            while(loop):
                try:
                    msg = self.print_queue.get_nowait()
                    print msg
                    printed = True
                except Queue.Empty:
                    loop = False
            if printed:
                readline.redisplay()
            self.output_lock.release()

            # Reprint the prompt and the user's current input if necessary
            if printed:
                self.readline_lock.acquire()
                readline.redisplay()
                self.readline_lock.release()

            # See if we need to terminate
            if self.print_terminate.isSet():
                return
            
            # Wait until we have something to print again
            self.print_event.wait()
            self.print_event.clear()

    def _run_caller(self):
        """A thread to monitor the command line and call any callbacks
        necessary"""
        
        while(True):

            # Wait for a short time to allow the callback to print anything
            time.sleep(0.08)

            # See if we need to terminate
            if self.caller_terminate.isSet():
                return

            # Read a line from input
            self.readline_lock.acquire()
            try:
                line = raw_input(self.prompt)
            except EOFError:
                print("\n")
                line = "\x04"
            finally:
                self.readline_lock.release()
            
            # Break the line down into its components
            argv = line.split()
            
            # Find a callback for this command
            try:
                cmd = argv[0]
            except IndexError:
                pass
            else:
                self.command_lock.acquire()
                self.output_lock.acquire()

                # Call the callback
                try:
                    callback = self.commands[cmd]
                except KeyError:
                    if self.default:
                        callback = self.default
                    else:
                        print("%s: command not found" % cmd)
                        callback = lambda x: None
                self.command_lock.release()
                self.output_lock.release()
            
                # Call the callback
                callback(argv)

    def add_command(self, command, callback):
        """Adds a command to the dictionary of commands, or updates the callback
        if the command is already present. See __init__ for a description of how
        callback is called."""
        self.command_lock.acquire()
        self.commands[command] = callback
        self.command_lock.release()

    def remove_command(self, command):
        """Removes a command from the dictionary of commands."""
        exc = None
        self.command_lock.acquire()
        try:
            del self.commands[command]
        except Exception as e:
            exc = e
        self.command_lock.release()
        if e is not None: raise e


class TIClient(object):

    def __init__(self, skt, conn_lost, recv_pkt):
        """Constructor.  Creates a TIClient from a socket and callbacks for
        when the connection is lost and a packet is received."""
        self.skt = skt
        self.conn_lost = conn_lost
        self.recv_pkt = recv_pkt

        # Create empty send and receive buffers
        self.sbuf = ''
        self.rbuf = ''

        # Flags to indicate when the threads need to exit
        self.recv_exit = Event()
        self.send_exit = Event()

        # Create a lock for admin operations on the socket
        self.skt_lock = Lock()

        # Create a thread to send data and an event so we can tell it to send
        # stuff
        self.slock = Lock()
        self.sevent = Event()
        self.sthread = Thread(target=self._run_send, name="TI_client_send")
        self.sthread.daemon = True
        self.sthread.start()
        
        # Create a receiver thread
        self.rthread = Thread(target=self._run_recv, name = "TI_client_recv")
        self.rthread.daemon = True
        self.rthread.start()

    def send(self, data):
        """Sends some data from this socket."""
        self.slock.acquire()
        self.sbuf += data
        self.slock.release()
        self.sevent.set()

    def _run_send(self):
        """A thread which tries to send any data waiting in the send buffer."""

        while(True):
            
            # See if we need to exit
            if self.send_exit.isSet():
                return
            
            self.slock.acquire()

            if len(self.sbuf) != 0:
                # If we have some data, send it
                len_sent = self.skt.send(self.sbuf)
                self.sbuf = self.sbuf[len_sent:]
                self.slock.release()
            else:
                # Otherwise, wait until we do have some data
                self.slock.release()
                self.sevent.wait()
                self.sevent.clear()

    def _run_recv(self):
        """A thread which receives any packets it can and calls the recv_pkt
        callback."""

        # Set the timeout on the socket so we don't block forever on calls to recv
        with self.skt_lock:
            self.skt.settimeout(1)
        
        while(True):

            debug("Receiver thread running")

            # Receive data and put it in the buffer
            loop = True
            while loop:
                try:
                    rcvd = self.skt.recv(4096)
                except socket.error:
                    # Call to recv timed out
                    pass
                else:
                    # We've got some actual data
                    loop = False

                # Whatever happens, we want to check if we need to exit
                if self.recv_exit.isSet():
                    # We need to exit - close the connection and return
                    with self.skt_lock:
                        self.skt.close()
                        return

            debug("\o/ data received")
            debug(hexdump(rcvd))
            self.rbuf += rcvd

            # The call to recv should normally block until we get some data or
            # a timeout occurs.  If it returns with no data then the socket has
            # closed.
            if len(rcvd) == 0:
                self.conn_lost()
                return

            # The beginning of the buffer should always be the start of a
            # packet, so we can check the packet's length field easily.
            # Here, we check it to see if we have a complete packet and if we
            # do then we call recv_pkt callback
            debug(len(self.rbuf))
            loop = True
            while len(self.rbuf) >= 4 and loop:
                (pkt_len,pkt_typ) = struct.unpack_from("!2H", self.rbuf)
                debug("Packet of length %s, buffer %d" % (pkt_len, len(self.rbuf)))
                if pkt_len <= len(self.rbuf):
                    debug("Calling callback")
                    self.recv_pkt(pkt_typ, self.rbuf[:pkt_len])
                    self.rbuf = self.rbuf[pkt_len:]
                else:
                    loop = False

    def stop(self):
        """Stops the threads and closes the connection."""

        # Stop the threads and wait until they're finished; the receiver thread
        # automatically closes the connection when it stops
        self.send_exit.set()
        self.sevent.set()
        self.recv_exit.set()


def hexdump(bin):
    """Converts a binary string to a human-readable hexdump string.  The human-
    readable string will always end in a newline, except where the binary data
    string is empty."""

    hr = ""
    line = bin[:16]
    bin = bin[16:]
    while(line != ""):
        hr += hexdump_line(line)
        line = bin[:16]
        bin = bin[16:]
    
    return hr

def hexdump_line(bin):
    """Converts a binary string with <= 16 bytes to a single line of hex dump."""

    # Convert all the characters to hex
    hexes = ["%02x" % ord(c) for c in bin]
    line = "|" + ' '.join(hexes)
    
    # Make the separator between the 8th and 9th characters a space not a hyphen
    if len(bin) > 8:
        line = '-'.join([line[:24], line[25:]])

    # Put a closing pipe on and pad with spaces to make to 60 chars
    line += '|'
    line += ' '*(60-len(line))

    # Do an ASCII dump
    ascii = ''.join([hexdump_ascii_char(c) for c in bin])
    ascii = "|%s|\n" % ascii

    return line + ascii

def hexdump_ascii_char(c):
    """Takes a single character and returns the character itself if it's a
    printable ASCII char of one character's width; otherwise returns a '.'"""

    o = ord(c)
    if (o < 0x20) or (o >= 0x7F): return '.'
    return c


if __name__ == "__main__":
    main()
    
