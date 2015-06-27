import struct
from enum import Enum


class DNSException(BaseException):
    """
    Any exceptions cause by this class
    """
    pass


HEADER_FORMAT = "!HHHHHH"
ID_FORMAT = "!H"


class DNSPacket:
    def __init__(self, data):
        """
        Fields of DNS packet according to RFC 1035
        """
        self.data = data
        self.HEADER = None
        self.QNAME = None
        self.len_name = None
        self.QTYPE = None
        self.QCLASS = None
        self.ATYPE = None
        self.ACLASS = None
        self.QR = None

        try:
            self.parse_header()
            self.parse_qname()
            self.parse_packet_type()
            self.parse_type()
            self.parse_class()
        except Exception as e:
            raise DNSException("Smth wrong with packet header")

    def parse_packet_type(self):
        """
        Parse QR flag
        """
        flags = struct.unpack("!BB", self.data[2:4])
        flag = flags[0] >> 7  # Get the first QR flag
        self.QR = flag

    def parse_header(self):
        """
        Parse data from dns header
        """
        self.HEADER = struct.unpack(HEADER_FORMAT, self.data[0:12])

    def parse_qname(self):
        """
        Parse QNAME from dns question part of packet
        Make an assumption that we have only 1 question
        """
        name_len = 0
        for b in self.data[12:]:
            name_len += 1
            if b == 0 or b == struct.pack("B", 0):
                break
        name = self.data[12:12 + name_len]
        self.len_name = name_len
        self.QNAME = struct.unpack(str(self.len_name) + "s", name)

    def add_id(self, p_id):
        """
        Add id before main data
        :param p_id: DNS packet id
        """
        reply_id = struct.pack(ID_FORMAT, p_id)
        self.data = reply_id + self.data[2:]

    def parse_type(self):
        """
        Parse type of dns question or dns answer
        0 - QUESTION or 1 - ANSWER
        """
        # class DNSTypes(Enum):
        #     A = 1
        #     NS = 2
        #     MD = 3
        #     MF = 4
        #     CNAME = 5
        #     SOA = 6
        #     MB = 7
        #     MG = 8
        #     MR = 9
        #     NULL = 10
        #     WKS = 11
        #     PTR = 12
        #     HINFO = 13
        #     MINFO = 14
        #     MX = 15
        #     TXT = 16
        types = {
            1: "A",
            2: "NS",
            3: "MD",
            4: "MF",
            5: "CNAME",
            6: "SOA",
            7: "MB",
            8: "MG",
            9: "MR",
            10: "NULL",
            11: "WKS",
            12: "PTR",
            13: "HINFO",
            14: "MINFO",
            15: "MX",
            16: "TXT"
        }
        if self.QR == 0:
            type_of_question = struct.unpack("!H", self.data[12 + self.len_name:12 + self.len_name + 2])[0]
            self.QTYPE = types[type_of_question]
        elif self.QR == 1:
            type_of_answer = struct.unpack("!H", self.data[12 + self.len_name + 4 + 2:12 + self.len_name + 4 + 4])[0]
            self.ATYPE = types[type_of_answer]
        else:
            raise DNSException("Invalid QR - either Question or ANSWER")

    def parse_class(self):
        """
        Parse class of dns question or answer
        0 - QUESTION or 1 - ANSWER
        """
        classes = {
            1: "IN",
            2: "CS",
            3: "CH",
            4: "HS"
        }
        if self.QR == 0:
            class_of_question = struct.unpack("!H", self.data[12 + self.len_name + 2:12 + self.len_name + 4])[0]
            self.QCLASS = classes[class_of_question]
        elif self.QR == 1:
            class_of_answer = struct.unpack("!H", self.data[12 + self.len_name + 4 + 4:12 + self.len_name + 4 + 6])[0]
            self.ACLASS = classes[class_of_answer]
        else:
            raise DNSException("Invalid QR - either Question or ANSWER")

    def get_ttl(self):
        """
        Get answer TTL
        """
        begin = 12 + self.len_name + 4 + 6
        end = 12 + self.len_name + 4 + 10
        return struct.unpack("!I", self.data[begin:end])[0]

    def get_rdata_len(self, begin, end):
        """
        Get the length of data in response (RDATA)
        """
        return struct.unpack("!H", self.data[begin:end])[0]

    def set_ttl(self, cache_time, cache_ttl, curr_time):
        begin = 12 + self.len_name + 4 + 10
        end = 12 + self.len_name + 4 + 12
        # For every answer set ttl
        for answer in range(self.HEADER[3]):
            rdata_len = self.get_rdata_len(begin, end)
            new_ttl = struct.pack("!I", int(cache_ttl - curr_time + cache_time))
            self.data = self.data[0:begin - 4] + new_ttl + self.data[end - 2:]
            begin += rdata_len + 12
            end += rdata_len + 12
