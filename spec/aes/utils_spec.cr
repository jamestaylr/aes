require "../../spec_helper"

describe AES::Utils do
  describe "mix_columns" do
    it "should perform mix columns step" do
      blk = [
        0x63, 0xeb, 0x9f, 0xa0, 0x2f, 0x93, 0x92, 0xc0,
        0xaf, 0xc7, 0xab, 0x30, 0xa2, 0x20, 0xcb, 0x2b,
      ]
      u = AES::Utils.new(256)
      x = u.mix_columns(blk)
      x.should eq [
        0xdf, 0xb4, 0x56, 0x8a, 0xa2, 0x7f, 0xd8, 0xeb,
        0x8c, 0xec, 0x75, 0xe6, 0xdf, 0x8f, 0x72, 0x40,
      ]
    end
  end

  describe "add_round_key" do
    it "handle initial round" do
      blk = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
      ]
      key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      ]
      u = AES::Utils.new(256)
      x = u.add_round_key(blk, key, 0)
      x.should eq [
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
        0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0,
      ]
    end

    it "handle expanded round key" do
      blk = [
        0x5f, 0x72, 0x64, 0x15, 0x57, 0xf5, 0xbc, 0x92,
        0xf7, 0xbe, 0x3b, 0x29, 0x1d, 0xb9, 0xf9, 0x1a,
      ]
      key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      ]

      u = AES::Utils.new(128)
      expanded = u.key_expansion(key)
      x = u.add_round_key(blk, expanded, 1)
      x.should eq [
        0x89, 0xd8, 0x10, 0xe8, 0x85, 0x5a, 0xce, 0x68,
        0x2d, 0x18, 0x43, 0xd8, 0xcb, 0x12, 0x8f, 0xe4,
      ]
    end

    it "handle last expanded round key" do
      blk = [
        0x7a, 0xd5, 0xfd, 0xa7, 0x89, 0xef, 0x4e, 0x27,
        0x2b, 0xca, 0x10, 0x0b, 0x3d, 0x9f, 0xf5, 0x9f,
      ]
      key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      ]

      u = AES::Utils.new(128)
      expanded = u.key_expansion(key)
      x = u.add_round_key(blk, expanded, 10)
      x.should eq [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
      ]
    end
  end
end
