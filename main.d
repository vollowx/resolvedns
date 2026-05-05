import std.array;
import std.bitmanip;
import std.socket;
import std.stdio;
import std.string;
import std.system;

align(1) struct DNSHeader {
  ushort id;
  ushort flags;
  ushort qdcount; // questions
  ushort ancount; // answers
  ushort nscount; // authority records
  ushort arcount; // additional records

  ubyte[] bigEndian() const {
    ubyte[] buf;
    buf.length = 12;

    size_t offset = 0;
    buf.write!(ushort, Endian.bigEndian)(id,      &offset);
    buf.write!(ushort, Endian.bigEndian)(flags,   &offset);
    buf.write!(ushort, Endian.bigEndian)(qdcount, &offset);
    buf.write!(ushort, Endian.bigEndian)(ancount, &offset);
    buf.write!(ushort, Endian.bigEndian)(nscount, &offset);
    buf.write!(ushort, Endian.bigEndian)(arcount, &offset);

    return buf;
  }

  /// Parse a DNS header from buffer, e.g. a query response.
  /// `b` will be consumed.
  this(ubyte[] b) {
    if (b.length != 12) throw new Exception("Expect a DNS header buffer that is 12 bytes long");

    this.id      = b.read!(ushort, Endian.bigEndian);
    this.flags   = b.read!(ushort, Endian.bigEndian);
    this.qdcount = b.read!(ushort, Endian.bigEndian);
    this.ancount = b.read!(ushort, Endian.bigEndian);
    this.nscount = b.read!(ushort, Endian.bigEndian);
    this.arcount = b.read!(ushort, Endian.bigEndian);
  }
}

ubyte[] encodeDomain(string domain) {
  auto buffer = appender!(ubyte [])();
  auto parts = domain.split(".");

  foreach (part; parts) {
    buffer.put(cast(ubyte) part.length);
    foreach (char c; part) {
      buffer.put(cast(ubyte) c);
    }
  }
  buffer.put(cast(ubyte) 0);

  return buffer.data;
}

int main() {
  DNSHeader header;
  header.id      = 0x1234;
  header.flags   = 0x0100; // Recursion desired
  header.qdcount = 1;      // 1 question

  write("Enter the domain: ");
  string target = readln().strip();
  auto encodedDomain = encodeDomain(target);

  // 4 bytes needed after the name, 2 for both
  ushort qtype = 1;  // A record for 1
  ushort qclass = 1; // IN       for 1

  ubyte[] packet;
  packet ~= header.bigEndian;
  packet ~= encodedDomain;
  packet ~= nativeToBigEndian(qtype);
  packet ~= nativeToBigEndian(qclass);

  auto socket = new UdpSocket();
  auto address = new InternetAddress("8.8.8.8", 53);

  socket.sendTo(packet, address);
  writeln("Query send, waiting for response...");

  ubyte[512] recvBuf;
  auto received = socket.receiveFrom(recvBuf);

  if (received < DNSHeader.sizeof) {
    writeln("Invalid response.");
    return 128;
  }

  writeln("Got ", received, " bytes.");

  auto respHeader = DNSHeader(recvBuf[0 .. 12]);
  int rcode = respHeader.flags & 0x000F;
  writefln("id = 0x%X, answers = %d, rcode = %d",
           respHeader.id,
           respHeader.ancount,
           rcode);

  if (rcode != 0 || respHeader.ancount == 0) {
    writeln("Error or no answers received.");
    return 1;
  }

  size_t offset = 12;

  while (recvBuf[offset] != 0) {
    offset += recvBuf[offset] + 1;
  } //            Skip question
  offset += 1; // Skip QTYPE
  offset += 4; // Skip QCLASS

  for (int i = 0; i < respHeader.ancount; ++i) {
    // Check for name compression, 11 in binary which is 0xC0
    if ((recvBuf[offset] & 0xC0) == 0xC0) {
      offset += 2;
    } else {
      // Skip the question (domain) label by label
      // 6 g o o g l e 3 c o m 0
      while (recvBuf[offset] != 0)
        offset += recvBuf[offset] + 1;
      offset += 1;
    }

    ushort rType   = peek!(ushort, Endian.bigEndian)(recvBuf[], offset); offset += 2;
    ushort rClass  = peek!(ushort, Endian.bigEndian)(recvBuf[], offset); offset += 2;
    uint   rTtl    = peek!(uint,   Endian.bigEndian)(recvBuf[], offset); offset += 4;
    ushort rLength = peek!(ushort, Endian.bigEndian)(recvBuf[], offset); offset += 2;

    // Type 1 is an A Record (IPv4) and length should be 4 bytes.
    if (rType == 1 && rLength == 4) {
      writefln("Found answer: %d.%d.%d.%d (TTL: %ds)",
        recvBuf[offset],
        recvBuf[offset+1],
        recvBuf[offset+2],
        recvBuf[offset+3],
        rTtl);
    }

    // Jump to the next answer (if there are)
    offset += rLength;
  }

  return 0;
}
