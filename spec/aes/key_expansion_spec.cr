require "../../spec_helper"

describe AES::Utils do
  describe "key_expansion" do
    it "should handle test case 1" do
      key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      ]
      u = AES::Utils.new(key)
      u.key_expansion(key).should eq [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa,
        0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab, 0x76, 0xfe,
        0xb6, 0x92, 0xcf, 0x0b, 0x64, 0x3d, 0xbd, 0xf1,
        0xbe, 0x9b, 0xc5, 0x00, 0x68, 0x30, 0xb3, 0xfe,
        0xb6, 0xff, 0x74, 0x4e, 0xd2, 0xc2, 0xc9, 0xbf,
        0x6c, 0x59, 0x0c, 0xbf, 0x04, 0x69, 0xbf, 0x41,
        0x47, 0xf7, 0xf7, 0xbc, 0x95, 0x35, 0x3e, 0x03,
        0xf9, 0x6c, 0x32, 0xbc, 0xfd, 0x05, 0x8d, 0xfd,
        0x3c, 0xaa, 0xa3, 0xe8, 0xa9, 0x9f, 0x9d, 0xeb,
        0x50, 0xf3, 0xaf, 0x57, 0xad, 0xf6, 0x22, 0xaa,
        0x5e, 0x39, 0x0f, 0x7d, 0xf7, 0xa6, 0x92, 0x96,
        0xa7, 0x55, 0x3d, 0xc1, 0x0a, 0xa3, 0x1f, 0x6b,
        0x14, 0xf9, 0x70, 0x1a, 0xe3, 0x5f, 0xe2, 0x8c,
        0x44, 0x0a, 0xdf, 0x4d, 0x4e, 0xa9, 0xc0, 0x26,
        0x47, 0x43, 0x87, 0x35, 0xa4, 0x1c, 0x65, 0xb9,
        0xe0, 0x16, 0xba, 0xf4, 0xae, 0xbf, 0x7a, 0xd2,
        0x54, 0x99, 0x32, 0xd1, 0xf0, 0x85, 0x57, 0x68,
        0x10, 0x93, 0xed, 0x9c, 0xbe, 0x2c, 0x97, 0x4e,
        0x13, 0x11, 0x1d, 0x7f, 0xe3, 0x94, 0x4a, 0x17,
        0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5,
      ]
    end

    it "should handle test case 2" do
      key = [
        0x1a, 0xd3, 0xef, 0xa2, 0x1c, 0xe5, 0x5d, 0x9c,
        0x8e, 0x53, 0xd1, 0x9e, 0x2a, 0x08, 0xe2, 0x00,
      ]
      u = AES::Utils.new(key)
      u.key_expansion(key).should eq [
        0x1a, 0xd3, 0xef, 0xa2, 0x1c, 0xe5, 0x5d, 0x9c,
        0x8e, 0x53, 0xd1, 0x9e, 0x2a, 0x08, 0xe2, 0x00,
        0x2b, 0x4b, 0x8c, 0x47, 0x37, 0xae, 0xd1, 0xdb,
        0xb9, 0xfd, 0x00, 0x45, 0x93, 0xf5, 0xe2, 0x45,
        0xcf, 0xd3, 0xe2, 0x9b, 0xf8, 0x7d, 0x33, 0x40,
        0x41, 0x80, 0x33, 0x05, 0xd2, 0x75, 0xd1, 0x40,
        0x56, 0xed, 0xeb, 0x2e, 0xae, 0x90, 0xd8, 0x6e,
        0xef, 0x10, 0xeb, 0x6b, 0x3d, 0x65, 0x3a, 0x2b,
        0x13, 0x6d, 0x1a, 0x09, 0xbd, 0xfd, 0xc2, 0x67,
        0x52, 0xed, 0x29, 0x0c, 0x6f, 0x88, 0x13, 0x27,
        0xc7, 0x10, 0xd6, 0xa1, 0x7a, 0xed, 0x14, 0xc6,
        0x28, 0x00, 0x3d, 0xca, 0x47, 0x88, 0x2e, 0xed,
        0x23, 0x21, 0x83, 0x01, 0x59, 0xcc, 0x97, 0xc7,
        0x71, 0xcc, 0xaa, 0x0d, 0x36, 0x44, 0x84, 0xe0,
        0x78, 0x7e, 0x62, 0x04, 0x21, 0xb2, 0xf5, 0xc3,
        0x50, 0x7e, 0x5f, 0xce, 0x66, 0x3a, 0xdb, 0x2e,
        0x78, 0xc7, 0x53, 0x37, 0x59, 0x75, 0xa6, 0xf4,
        0x09, 0x0b, 0xf9, 0x3a, 0x6f, 0x31, 0x22, 0x14,
        0xa4, 0x54, 0xa9, 0x9f, 0xfd, 0x21, 0x0f, 0x6b,
        0xf4, 0x2a, 0xf6, 0x51, 0x9b, 0x1b, 0xd4, 0x45,
        0x3d, 0x1c, 0xc7, 0x8b, 0xc0, 0x3d, 0xc8, 0xe0,
        0x34, 0x17, 0x3e, 0xb1, 0xaf, 0x0c, 0xea, 0xf4,
      ]
    end

    it "should handle test case 3" do
      key = [
        0x4f, 0x5a, 0x52, 0x4f, 0xa0, 0x65,
        0x3d, 0xdd, 0x7d, 0xd0, 0x2a, 0xdf,
        0x6b, 0x9a, 0x6b, 0x76, 0xe4, 0xcc,
        0x26, 0x37, 0x4c, 0x58, 0x1d, 0x7d,
      ]
      u = AES::Utils.new(key)
      u.key_expansion(key).should eq [
        0x4f, 0x5a, 0x52, 0x4f, 0xa0, 0x65, 0x3d, 0xdd,
        0x7d, 0xd0, 0x2a, 0xdf, 0x6b, 0x9a, 0x6b, 0x76,
        0xe4, 0xcc, 0x26, 0x37, 0x4c, 0x58, 0x1d, 0x7d,
        0x24, 0xfe, 0xad, 0x66, 0x84, 0x9b, 0x90, 0xbb,
        0xf9, 0x4b, 0xba, 0x64, 0x92, 0xd1, 0xd1, 0x12,
        0x76, 0x1d, 0xf7, 0x25, 0x3a, 0x45, 0xea, 0x58,
        0x48, 0x79, 0xc7, 0xe6, 0xcc, 0xe2, 0x57, 0x5d,
        0x35, 0xa9, 0xed, 0x39, 0xa7, 0x78, 0x3c, 0x2b,
        0xd1, 0x65, 0xcb, 0x0e, 0xeb, 0x20, 0x21, 0x56,
        0xfb, 0x84, 0x76, 0x0f, 0x37, 0x66, 0x21, 0x52,
        0x02, 0xcf, 0xcc, 0x6b, 0xa5, 0xb7, 0xf0, 0x40,
        0x74, 0xd2, 0x3b, 0x4e, 0x9f, 0xf2, 0x1a, 0x18,
        0x7a, 0x26, 0xdb, 0xd4, 0x4d, 0x40, 0xfa, 0x86,
        0x4f, 0x8f, 0x36, 0xed, 0xea, 0x38, 0xc6, 0xad,
        0x9e, 0xea, 0xfd, 0xe3, 0x01, 0x18, 0xe7, 0xfb,
        0xc7, 0xb2, 0xd4, 0xa8, 0x8a, 0xf2, 0x2e, 0x2e,
        0xc5, 0x7d, 0x18, 0xc3, 0x2f, 0x45, 0xde, 0x6e,
        0xb1, 0xaf, 0x23, 0x8d, 0xb0, 0xb7, 0xc4, 0x76,
        0x4e, 0xae, 0xec, 0x4f, 0xc4, 0x5c, 0xc2, 0x61,
        0x01, 0x21, 0xda, 0xa2, 0x2e, 0x64, 0x04, 0xcc,
        0x9f, 0xcb, 0x27, 0x41, 0x2f, 0x7c, 0xe3, 0x37,
        0x1e, 0xbf, 0x76, 0x5a, 0xda, 0xe3, 0xb4, 0x3b,
        0xdb, 0xc2, 0x6e, 0x99, 0xf5, 0xa6, 0x6a, 0x55,
        0x6a, 0x6d, 0x4d, 0x14, 0x45, 0x11, 0xae, 0x23,
        0x1c, 0x5b, 0x50, 0x34, 0xc6, 0xb8, 0xe4, 0x0f,
        0x1d, 0x7a, 0x8a, 0x96, 0xe8, 0xdc, 0xe0, 0xc3,
      ]
    end

    it "should handle test case 4" do
      key = [
        0x54, 0xd1, 0xc2, 0x0a, 0x0d, 0x7b, 0x90, 0xa2,
        0x7e, 0x80, 0x99, 0xbf, 0xec, 0x62, 0x45, 0xad,
        0xde, 0x4f, 0xca, 0xb6, 0x8f, 0x6c, 0x18, 0xa2,
        0xc5, 0xb0, 0x7b, 0x56, 0xaa, 0x1e, 0x30, 0x0f,
      ]
      u = AES::Utils.new(key)
      u.key_expansion(key).should eq [
        0x54, 0xd1, 0xc2, 0x0a, 0x0d, 0x7b, 0x90, 0xa2,
        0x7e, 0x80, 0x99, 0xbf, 0xec, 0x62, 0x45, 0xad,
        0xde, 0x4f, 0xca, 0xb6, 0x8f, 0x6c, 0x18, 0xa2,
        0xc5, 0xb0, 0x7b, 0x56, 0xaa, 0x1e, 0x30, 0x0f,
        0x27, 0xd5, 0xb4, 0xa6, 0x2a, 0xae, 0x24, 0x04,
        0x54, 0x2e, 0xbd, 0xbb, 0xb8, 0x4c, 0xf8, 0x16,
        0xb2, 0x66, 0x8b, 0xf1, 0x3d, 0x0a, 0x93, 0x53,
        0xf8, 0xba, 0xe8, 0x05, 0x52, 0xa4, 0xd8, 0x0a,
        0x6c, 0xb4, 0xd3, 0xa6, 0x46, 0x1a, 0xf7, 0xa2,
        0x12, 0x34, 0x4a, 0x19, 0xaa, 0x78, 0xb2, 0x0f,
        0x1e, 0xda, 0xbc, 0x87, 0x23, 0xd0, 0x2f, 0xd4,
        0xdb, 0x6a, 0xc7, 0xd1, 0x89, 0xce, 0x1f, 0xdb,
        0xe3, 0x74, 0x6a, 0x01, 0xa5, 0x6e, 0x9d, 0xa3,
        0xb7, 0x5a, 0xd7, 0xba, 0x1d, 0x22, 0x65, 0xb5,
        0xba, 0x49, 0xf1, 0x52, 0x99, 0x99, 0xde, 0x86,
        0x42, 0xf3, 0x19, 0x57, 0xcb, 0x3d, 0x06, 0x8c,
        0xcc, 0x1b, 0x0e, 0x1e, 0x69, 0x75, 0x93, 0xbd,
        0xde, 0x2f, 0x44, 0x07, 0xc3, 0x0d, 0x21, 0xb2,
        0x94, 0x9e, 0x0c, 0x65, 0x0d, 0x07, 0xd2, 0xe3,
        0x4f, 0xf4, 0xcb, 0xb4, 0x84, 0xc9, 0xcd, 0x38,
        0x01, 0xa6, 0x09, 0x41, 0x68, 0xd3, 0x9a, 0xfc,
        0xb6, 0xfc, 0xde, 0xfb, 0x75, 0xf1, 0xff, 0x49,
        0x09, 0x3f, 0x1a, 0x5e, 0x04, 0x38, 0xc8, 0xbd,
        0x4b, 0xcc, 0x03, 0x09, 0xcf, 0x05, 0xce, 0x31,
        0x4a, 0x2d, 0xce, 0xcb, 0x22, 0xfe, 0x54, 0x37,
        0x94, 0x02, 0x8a, 0xcc, 0xe1, 0xf3, 0x75, 0x85,
        0xf1, 0x32, 0x87, 0xc9, 0xf5, 0x0a, 0x4f, 0x74,
        0xbe, 0xc6, 0x4c, 0x7d, 0x71, 0xc3, 0x82, 0x4c,
        0x24, 0x3e, 0xe7, 0x68, 0x06, 0xc0, 0xb3, 0x5f,
        0x92, 0xc2, 0x39, 0x93, 0x73, 0x31, 0x4c, 0x16,
      ]
    end
  end
end
