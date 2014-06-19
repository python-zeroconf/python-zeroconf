#!/usr/bin/env python

""" Unit tests for zeroconf.py """

import zeroconf as r
import struct
import unittest

class PacketGeneration(unittest.TestCase):

    def testParseOwnPacketSimple(self):
        generated = r.DNSOutgoing(0)
        parsed = r.DNSIncoming(generated.packet())

    def testParseOwnPacketSimpleUnicast(self):
        generated = r.DNSOutgoing(0, 0)
        parsed = r.DNSIncoming(generated.packet())

    def testParseOwnPacketFlags(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        parsed = r.DNSIncoming(generated.packet())

    def testParseOwnPacketQuestion(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        generated.addQuestion(r.DNSQuestion("testname.local.", r._TYPE_SRV,
                                            r._CLASS_IN))
        parsed = r.DNSIncoming(generated.packet())

    def testMatchQuestion(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        question = r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN)
        generated.addQuestion(question)
        parsed = r.DNSIncoming(generated.packet())
        self.assertEqual(len(generated.questions), 1)
        self.assertEqual(len(generated.questions), len(parsed.questions))
        self.assertEqual(question, parsed.questions[0])

class PacketForm(unittest.TestCase):

    def testTransactionID(self):
        """ID must be zero in a DNS-SD packet"""
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        bytes = generated.packet()
        id = ord(bytes[0]) << 8 | ord(bytes[1])
        self.assertEqual(id, 0)

    def testQueryHeaderBits(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        bytes = generated.packet()
        flags = ord(bytes[2]) << 8 | ord(bytes[3])
        self.assertEqual(flags, 0x0)

    def testResponseHeaderBits(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        bytes = generated.packet()
        flags = ord(bytes[2]) << 8 | ord(bytes[3])
        self.assertEqual(flags, 0x8000)

    def testNumbers(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        bytes = generated.packet()
        (numQuestions, numAnswers, numAuthorities,
           numAdditionals) = struct.unpack('!4H', bytes[4:12])
        self.assertEqual(numQuestions, 0)
        self.assertEqual(numAnswers, 0)
        self.assertEqual(numAuthorities, 0)
        self.assertEqual(numAdditionals, 0)

    def testNumbersQuestions(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN)
        for i in xrange(10):
            generated.addQuestion(question)
        bytes = generated.packet()
        (numQuestions, numAnswers, numAuthorities,
           numAdditionals) = struct.unpack('!4H', bytes[4:12])
        self.assertEqual(numQuestions, 10)
        self.assertEqual(numAnswers, 0)
        self.assertEqual(numAuthorities, 0)
        self.assertEqual(numAdditionals, 0)

class Names(unittest.TestCase):

    def testLongName(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion("this.is.a.very.long.name.with.lots.of.parts.in.it.local.",
                                 r._TYPE_SRV, r._CLASS_IN)
        generated.addQuestion(question)
        parsed = r.DNSIncoming(generated.packet())

    def testExceedinglyLongName(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        name = "%slocal." % ("part." * 1000)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.addQuestion(question)
        parsed = r.DNSIncoming(generated.packet())

    def testExceedinglyLongNamePart(self):
        name = "%s.local." % ("a" * 1000)
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.addQuestion(question)
        self.assertRaises(r.NamePartTooLongException, generated.packet)

    def testSameName(self):
        name = "paired.local."
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.addQuestion(question)
        generated.addQuestion(question)
        parsed = r.DNSIncoming(generated.packet())

class Framework(unittest.TestCase):

    def testLaunchAndClose(self):
        rv = r.Zeroconf()
        rv.close()

if __name__ == '__main__':
    unittest.main()
