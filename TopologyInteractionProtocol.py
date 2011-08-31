"""Defines the TI protocol and some associated helper functions."""

from socket import gethostbyname, inet_aton, inet_ntoa
import struct

from ltprotocol.ltprotocol import LTMessage, LTProtocol, LTTwistedServer

from LoggingHelper import pktstr
from VNSProtocol import strip_null_chars, VNSAuthRequest, VNSAuthReply, VNSAuthStatus

TI_DEFAULT_PORT = 12346
TI_MESSAGES = [VNSAuthRequest, VNSAuthReply, VNSAuthStatus]  # uses same auth messages

class TIOpen(LTMessage):
    @staticmethod
    def get_type():
        return 1

    def __init__(self, topo_id):
        LTMessage.__init__(self)
        self.topo_id = int(topo_id)

    def length(self):
        return TIOpen.SIZE

    FORMAT = '> H'
    SIZE = struct.calcsize(FORMAT)

    def pack(self):
        return struct.pack(TIOpen.FORMAT, self.topo_id)

    @staticmethod
    def unpack(body):
        t = struct.unpack(TIOpen.FORMAT, body)
        return TIOpen(t[0])

    def __str__(self):
        return 'OPEN: topo_id=%u' % self.topo_id
TI_MESSAGES.append(TIOpen)

class TINodePortHeader(LTMessage):
    def __init__(self, node_name, intf_name):
        LTMessage.__init__(self)
        assert len(node_name)<=30, 'node_name may only be up to 30 characters'
        assert len(intf_name)<=5,  'intf_name may only be up to 5 characters'
        self.node_name = node_name.lower()
        self.intf_name = intf_name.lower()

    def length(self):
        return TINodePortHeader.HEADER_SIZE

    HEADER_FORMAT = '> 30s 5s'
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def pack(self):
        return struct.pack(TINodePortHeader.HEADER_FORMAT, self.node_name, self.intf_name)

    @staticmethod
    def unpack_hdr(body):
        t = struct.unpack(TINodePortHeader.HEADER_FORMAT, body[:TINodePortHeader.HEADER_SIZE])
        node_name = strip_null_chars(t[0])
        intf_name = strip_null_chars(t[1])
        return (node_name, intf_name, body[TINodePortHeader.HEADER_SIZE:])

    def __str__(self):
        return '%s:%s' % (self.node_name, self.intf_name)

class TIPacket(TINodePortHeader):
    @staticmethod
    def get_type():
        return 2

    def __init__(self, node_name, intf_name, ethernet_frame):
        TINodePortHeader.__init__(self, node_name, intf_name)
        self.ethernet_frame = ethernet_frame

    def length(self):
        return TINodePortHeader.length(self) + len(self.ethernet_frame)

    def pack(self):
        hdr = TINodePortHeader.pack(self)
        return hdr + self.ethernet_frame

    @staticmethod
    def unpack(body):
        node_name, port_name, body = TINodePortHeader.unpack_hdr(body)
        return TIPacket(node_name, port_name, body)

    def __str__(self):
        return 'PACKET from %s: %s' % (TINodePortHeader.__str__(self), pktstr(self.ethernet_frame))
TI_MESSAGES.append(TIPacket)

class TIPingFromRequest(TINodePortHeader):
    @staticmethod
    def get_type():
        return 6

    def __init__(self, node_name, intf_name, dst):
        TINodePortHeader.__init__(self, node_name, intf_name)
        if len(dst)==4:
            self.dst_ip = dst
        else:
            self.dst_ip = inet_aton(gethostbyname(dst))

    def length(self):
        return TINodePortHeader.length(self) + 4

    def pack(self):
        hdr = TINodePortHeader.pack(self)
        return hdr + self.dst_ip

    @staticmethod
    def unpack(body):
        node_name, port_name, body = TINodePortHeader.unpack_hdr(body)
        return TIPingFromRequest(node_name, port_name, body)

    def __str__(self):
        return 'PING request from %s to %s' % (TINodePortHeader.__str__(self), inet_ntoa(self.dst_ip))
TI_MESSAGES.append(TIPingFromRequest)

class TITap(TINodePortHeader):
    @staticmethod
    def get_type():
        return 3

    def __init__(self, node_name, intf_name, tap, consume=False, ip_only=False, bidirectional=False):
        """If tap is True, then packets arriving at the specified node on the
        specified interface will be forwarded to this connection.  If consume is
        True, then any tapped packets will not be sent to the topology too.  If
        ip_only is True, then only packets with an IP header will be tapped.  If
        bidirectional is True, then packets in both directions on the interface
        will be tapped."""
        TINodePortHeader.__init__(self, node_name, intf_name)
        self.tap = tap
        self.consume = consume
        self.ip_only = ip_only
        self.bidirectional = bidirectional

    def length(self):
        return TINodePortHeader.length(self) + TITap.SIZE

    FORMAT = '> 3b'
    SIZE = struct.calcsize(FORMAT)

    def pack(self):
        hdr = TINodePortHeader.pack(self)
        return hdr + struct.pack(TITap.FORMAT, self.tap, self.consume,
                                 (1 if self.ip_only else 0) | 
                                 (2 if self.bidirectional else 0))

    @staticmethod
    def unpack(body):
        node_name, port_name, body = TINodePortHeader.unpack_hdr(body)
        tap, consume, ip_only = struct.unpack(TITap.FORMAT, body)
        bidirectional = (ip_only & 2) >> 1
        ip_only = ip_only & 1
        return TITap(node_name, port_name, tap, consume, ip_only, bidirectional)

    def __str__(self):
        prefix = 'TAP' if self.tap else 'UNTAP'
        suffix = ' [CONSUME]' if self.tap and self.consume else ''
        suffix += ' [IP ONLY]' if self.tap and self.ip_only else ''
        return '%s %s%s' % (prefix, TINodePortHeader.__str__(self), suffix)
TI_MESSAGES.append(TITap)

class TIModifyLink(TINodePortHeader):
    @staticmethod
    def get_type():
        return 4

    def __init__(self, node_name, intf_name, link_state):
        """If link_state enable is True, then the link will be enabled (no
        loss).  If False, then the link will be disabled (100% loss). Otherwise,
        link_state must be a float value in the range [0.0,1.0] specifying how
        lossy the link is."""
        TINodePortHeader.__init__(self, node_name, intf_name)
        if link_state is True:
            self.lossiness = 0.0
        elif link_state is False:
            self.lossiness = 1.0
        elif link_state<0.0 or link_state>1.0:
            raise ValueError('link_state must be between 0.0 and 1.0')
        else:
            self.lossiness = float(link_state)

    def length(self):
        return TINodePortHeader.length(self) + TIModifyLink.SIZE

    FORMAT = '> f'
    SIZE = struct.calcsize(FORMAT)

    def pack(self):
        hdr = TINodePortHeader.pack(self)
        return hdr + struct.pack(TIModifyLink.FORMAT, self.lossiness)

    @staticmethod
    def unpack(body):
        node_name, port_name, body = TINodePortHeader.unpack_hdr(body)
        lossiness = struct.unpack(TIModifyLink.FORMAT, body)[0]
        return TIModifyLink(node_name, port_name, lossiness)

    def __str__(self):
        return 'set link lossiness=%.2f%% for link connected to %s' % (self.lossiness, TINodePortHeader.__str__(self))
TI_MESSAGES.append(TIModifyLink)

class TIBanner(LTMessage):
    @staticmethod
    def get_type():
        return 5

    def __init__(self, msg):
        LTMessage.__init__(self)
        self.msg = str(msg)

    def length(self):
        return len(self.msg)

    def pack(self):
        return self.msg

    @staticmethod
    def unpack(body):
        return TIBanner(body)

    def __str__(self):
        return self.msg
TI_MESSAGES.append(TIBanner)

class TIBadNodeOrPort(TINodePortHeader):
    """Indicates that the requested node or port was invalid.  If port is
    omitted, then the node does not exist.  Otherwise the node exists but the
    port does not."""
    # problem IDs
    BAD_NODE = 0
    BAD_INTF = 1
    MISSING_LINK = 2

    @staticmethod
    def get_type():
        return 7

    def __init__(self, node_name, intf_name, problem_id):
        TINodePortHeader.__init__(self, node_name, intf_name)
        self.problem_id = int(problem_id)

    FORMAT = '> I'
    SIZE = struct.calcsize(FORMAT)

    def length(self):
        return TINodePortHeader.length(self) + TIBadNodeOrPort.SIZE

    def pack(self):
        hdr = TINodePortHeader.pack(self)
        return hdr + struct.pack(TIBadNodeOrPort.FORMAT, self.problem_id)

    @staticmethod
    def unpack(body):
        node_name, port_name, body = TINodePortHeader.unpack_hdr(body)
        problem_id = struct.unpack(TIBadNodeOrPort.FORMAT, body)[0]
        return TIBadNodeOrPort(node_name, port_name, problem_id)

    def __str__(self):
        if self.problem_id == TIBadNodeOrPort.BAD_NODE:
            return 'Invalid node: %s' % self.node_name
        what = TINodePortHeader.__str__(self)
        if self.problem_id == TIBadNodeOrPort.BAD_INTF:
            return 'Invalid interface: %s' % what
        elif self.problem_id == TIBadNodeOrPort.MISSING_LINK:
            return 'There is no link connected to %s' % what
        else:
            return 'Unknown problem (code %d) with %s' % (self.problem_id, what)
TI_MESSAGES.append(TIBadNodeOrPort)

TI_PROTOCOL = LTProtocol(TI_MESSAGES, 'H', 'H')

def create_ti_server(port, recv_callback, new_conn_callback, lost_conn_callback, verbose=True):
    """Starts a server which listens for TI clients on the specified port.

    @param port  the port to listen on
    @param recv_callback  the function to call with received message content
                         (takes two arguments: transport, msg)
    @param new_conn_callback   called with one argument (a LTProtocol) when a connection is started
    @param lost_conn_callback  called with one argument (a LTProtocol) when a connection is lost
    @param verbose        whether to print messages when they are sent

    @return returns the new LTTwistedServer
    """
    server = LTTwistedServer(TI_PROTOCOL, recv_callback, new_conn_callback, lost_conn_callback, verbose)
    server.listen(port)
    return server
