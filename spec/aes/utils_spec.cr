require "../../spec_helper"

describe AES::Utils do
  describe "key_expansion" do
    it "should handle test case 1" do
      key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      ]
      u = AES::Utils.new(128)
      e = u.key_expansion(key)
      e.map { |j| j.to_s(16).rjust(2, '0') }.join.should eq [
        "000102030405060708090a0b0c0d0e0f",
        "d6aa74fdd2af72fadaa678f1d6ab76fe",
        "b692cf0b643dbdf1be9bc5006830b3fe",
        "b6ff744ed2c2c9bf6c590cbf0469bf41",
        "47f7f7bc95353e03f96c32bcfd058dfd",
        "3caaa3e8a99f9deb50f3af57adf622aa",
        "5e390f7df7a69296a7553dc10aa31f6b",
        "14f9701ae35fe28c440adf4d4ea9c026",
        "47438735a41c65b9e016baf4aebf7ad2",
        "549932d1f08557681093ed9cbe2c974e",
        "13111d7fe3944a17f307a78b4d2b30c5",
      ].join
    end

    it "should handle test case 2" do
      key = [
        0x1a, 0xd3, 0xef, 0xa2, 0x1c, 0xe5, 0x5d, 0x9c,
        0x8e, 0x53, 0xd1, 0x9e, 0x2a, 0x08, 0xe2, 0x00,
      ]
      u = AES::Utils.new(128)
      e = u.key_expansion(key)
      e.map { |j| j.to_s(16).rjust(2, '0') }.join.should eq [
        "1ad3efa21ce55d9c8e53d19e2a08e200",
        "2b4b8c4737aed1dbb9fd004593f5e245",
        "cfd3e29bf87d334041803305d275d140",
        "56edeb2eae90d86eef10eb6b3d653a2b",
        "136d1a09bdfdc26752ed290c6f881327",
        "c710d6a17aed14c628003dca47882eed",
        "2321830159cc97c771ccaa0d364484e0",
        "787e620421b2f5c3507e5fce663adb2e",
        "78c753375975a6f4090bf93a6f312214",
        "a454a99ffd210f6bf42af6519b1bd445",
        "3d1cc78bc03dc8e034173eb1af0ceaf4",
      ].join
    end

    it "should handle test case 3" do
      key = [
        0x4f, 0x5a, 0x52, 0x4f, 0xa0, 0x65,
        0x3d, 0xdd, 0x7d, 0xd0, 0x2a, 0xdf,
        0x6b, 0x9a, 0x6b, 0x76, 0xe4, 0xcc,
        0x26, 0x37, 0x4c, 0x58, 0x1d, 0x7d,
      ]
      u = AES::Utils.new(192)
      e = u.key_expansion(key)
      e.map { |j| j.to_s(16).rjust(2, '0') }.join.should eq [
        "4f5a524fa0653ddd7dd02adf6b9a6b76",
        "e4cc26374c581d7d24fead66849b90bb",
        "f94bba6492d1d112761df7253a45ea58",
        "4879c7e6cce2575d35a9ed39a7783c2b",
        "d165cb0eeb202156fb84760f37662152",
        "02cfcc6ba5b7f04074d23b4e9ff21a18",
        "7a26dbd44d40fa864f8f36edea38c6ad",
        "9eeafde30118e7fbc7b2d4a88af22e2e",
        "c57d18c32f45de6eb1af238db0b7c476",
        "4eaeec4fc45cc2610121daa22e6404cc",
        "9fcb27412f7ce3371ebf765adae3b43b",
        "dbc26e99f5a66a556a6d4d144511ae23",
        "1c5b5034c6b8e40f1d7a8a96e8dce0c3",
      ].join
    end

    it "should handle test case 4" do
      key = [
        0x54, 0xd1, 0xc2, 0x0a, 0x0d, 0x7b, 0x90, 0xa2,
        0x7e, 0x80, 0x99, 0xbf, 0xec, 0x62, 0x45, 0xad,
        0xde, 0x4f, 0xca, 0xb6, 0x8f, 0x6c, 0x18, 0xa2,
        0xc5, 0xb0, 0x7b, 0x56, 0xaa, 0x1e, 0x30, 0x0f,
      ]
      u = AES::Utils.new(256)
      e = u.key_expansion(key)
      e.map { |j| j.to_s(16).rjust(2, '0') }.join.should eq [
        "54d1c20a0d7b90a27e8099bfec6245ad",
        "de4fcab68f6c18a2c5b07b56aa1e300f",
        "27d5b4a62aae2404542ebdbbb84cf816",
        "b2668bf13d0a9353f8bae80552a4d80a",
        "6cb4d3a6461af7a212344a19aa78b20f",
        "1edabc8723d02fd4db6ac7d189ce1fdb",
        "e3746a01a56e9da3b75ad7ba1d2265b5",
        "ba49f1529999de8642f31957cb3d068c",
        "cc1b0e1e697593bdde2f4407c30d21b2",
        "949e0c650d07d2e34ff4cbb484c9cd38",
        "01a6094168d39afcb6fcdefb75f1ff49",
        "093f1a5e0438c8bd4bcc0309cf05ce31",
        "4a2dcecb22fe543794028acce1f37585",
        "f13287c9f50a4f74bec64c7d71c3824c",
        "243ee76806c0b35f92c2399373314c16",
      ].join
    end
  end

  describe "mix_columns" do
    it "should perform mix columns step" do
      blk = [
        0x63, 0xeb, 0x9f, 0xa0,
        0x2f, 0x93, 0x92, 0xc0,
        0xaf, 0xc7, 0xab, 0x30,
        0xa2, 0x20, 0xcb, 0x2b,
      ]
      u = AES::Utils.new(256)
      x = u.mix_columns(blk)
      x.should eq [
        0xdf, 0xb4, 0x56, 0x8a,
        0xa2, 0x7f, 0xd8, 0xeb,
        0x8c, 0xec, 0x75, 0xe6,
        0xdf, 0x8f, 0x72, 0x40,
      ]
    end
  end
end
