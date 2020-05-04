#define MIN(a, b) ((a) <= (b) ? (a) : (b))

int main()
{
  char const str[] =
    "La pluie nous a débués et lavés,\n"
    "Et le soleil desséchés et noircis.\n"
    "  Pies, corbeaux nous ont les yeux cavés,\n"
    "Et arraché la barbe et les sourcils.\n"
    "  Jamais nul temps nous ne sommes assis\n"
    "  Puis çà, puis là, comme le vent varie,\n"
    "A son plaisir sans cesser nous charrie,\n"
    "Plus becquetés d'oiseaux que dés à coudre.\n"
    "  Ne soyez donc de notre confrérie;\n"
    "Mais priez Dieu que tous nous veuille absoudre!\n";

  size_t buf0_sz = sizeof(str);
  char buf0[IO_BUF_SIZE];
  memcpy(buf0, str, buf0_sz);
  size_t buf1_sz = 0, buf2_sz = 0;
  char buf1[IO_BUF_SIZE];
  char buf2[IO_BUF_SIZE];

  // Visual check:
  printf("Source:\n%.*s\n", buf0_sz, buf0);
  encode(buf0, &buf0_sz, buf1, &buf1_sz);
  assert(buf1_sz == 568);
  printf("Encoded:\n%.*s\n", buf1_sz, buf1);
  decode(buf1, buf1_sz, &buf1_sz, buf2, &buf2_sz);
  assert(buf2_sz == sizeof(str));
  printf("Decoded:\n%.*s\n", buf2_sz, buf2);
  assert(0 == strncmp(str, buf2, buf2_sz));

  // Test every line lengths:
  size_t len;
  for (len = 1; len <= sizeof(str); len++) {
    buf0_sz = len;
    memcpy(buf0, str, buf0_sz);
    buf1_sz = buf2_sz = 0;
    encode(buf0, &buf0_sz, buf1, &buf1_sz);
    assert(buf0_sz == 0);
    decode(buf1, buf1_sz, &buf1_sz, buf2, &buf2_sz);
    assert(buf2_sz == len);
    assert(0 == strncmp(str, buf2, buf2_sz));
  }
  printf("Line sizes from 1 to %zu OK.\n", len);

  // Test filling encoded buffer:
  buf0_sz = buf1_sz = buf2_sz = 0;
  size_t seq_in = 0, seq_out = 0;
  for (int n = 0; n < 1000; n ++) {
    // Fill input:
    for (; buf0_sz < IO_BUF_SIZE; buf0_sz++) buf0[buf0_sz] = seq_in++;
    encode(buf0, &buf0_sz, buf1, &buf1_sz);
    assert(! IS_EMPTY(buf1_sz) && ! IS_FULL(buf0_sz));  // must have done something
    decode(buf1, buf1_sz, &buf1_sz, buf2, &buf2_sz);
    assert(! IS_EMPTY(buf2_sz) && ! IS_FULL(buf1_sz));
    size_t i;
    for (i = 0; i < buf2_sz; i++) assert(buf2[i] == (char)seq_out++);
    buffer_shift(buf2, &buf2_sz, i);
    assert(IS_EMPTY(buf2_sz));
  }
  printf("Fill test OK.\n");

  // Test hex decoding
  assert(0x1234 == peek_hex("1234"));
  assert(0x1AF8 == peek_hex("1AF8"));
  char c[4 + 1];
  poke_hex(c, 0x1234);
  assert(0 == strncmp(c, "1234", 4));
  poke_hex(c, 0x1AF8);
  assert(0 == strncmp(c, "1AF8", 4));
  printf("Hex enc/dec OK.\n");

  // Test frames
  for (size_t flush_sz = 1; flush_sz < IO_BUF_SIZE; flush_sz++) {
    buf0_sz = buf1_sz = 0;
    seq_in = 0, seq_out = 0;
    size_t dest = 42;
    cnxs[dest].from_clt_sz = cnxs[42].from_srv_sz = 0;
    cnxs[dest].fd = 17; // pretend the cnx is live
    for (int n = 0; seq_out < 10000; n++) {
      // Fill the input buffer
      for (; buf0_sz < IO_BUF_SIZE; buf0_sz++) buf0[buf0_sz] = seq_in++;
      ssize_t frame_sz = try_encode_frame(dest, buf0, &buf0_sz, buf1, &buf1_sz);
      // Decode into cnxs[dest] buffer
      size_t frame_sz_;
      size_t dest_;
      bool done = try_decode_frame(buf1, &buf1_sz, &frame_sz_, &dest_, false);
      if (done) {
        assert(dest_ == dest);
        assert(! IS_EMPTY(cnxs[dest].from_srv_sz));
        assert(! IS_FULL(buf1_sz));
      }
      size_t flush_sz_ = MIN(flush_sz, cnxs[dest].from_srv_sz);
      size_t i;
      for (i = 0; i < flush_sz_; i++)
        assert(cnxs[dest].from_srv[i] == (char)seq_out++);
      buffer_shift(cnxs[dest].from_srv, &cnxs[dest].from_srv_sz, flush_sz_);
    }
  }
  printf("Frames OK.\n");

  printf("All tests succeeded.\n");
  return 0;
}
