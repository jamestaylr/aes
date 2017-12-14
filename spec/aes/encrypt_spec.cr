require "../../spec_helper"

describe AES::Utils do
  describe "encrypt" do
    it "should encrypt case 1 in ECB mode" do
      u = AES::Utils.new(128, AES::Mode::ECB)
      plaintext = [
        0x15, 0x26, 0x15, 0x40, 0x61, 0xb6, 0x89, 0xe0,
        0xf0, 0x0a, 0x5c, 0x2f, 0xf1, 0xec, 0x19, 0xe4,
      ]
      key = [
        0x30, 0x19, 0x0d, 0xcc, 0x14, 0x58, 0x53, 0x01,
        0xf5, 0xbf, 0xc5, 0xb6, 0x66, 0xc8, 0x47, 0x75,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0x8d, 0x04, 0xff, 0xf2, 0x7a, 0x08, 0x1a, 0x77,
        0xde, 0x20, 0x09, 0xd1, 0x40, 0x2e, 0x6e, 0x03,
      ]
    end

    it "should encrypt case 1 in ECB mode" do
      u = AES::Utils.new(128, AES::Mode::CBC)
      plaintext = [
        0x15, 0x26, 0x15, 0x40, 0x61, 0xb6, 0x89, 0xe0,
        0xf0, 0x0a, 0x5c, 0x2f, 0xf1, 0xec, 0x19, 0xe4,
      ]
      key = [
        0x30, 0x19, 0x0d, 0xcc, 0x14, 0x58, 0x53, 0x01,
        0xf5, 0xbf, 0xc5, 0xb6, 0x66, 0xc8, 0x47, 0x75,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0x8d, 0x04, 0xff, 0xf2, 0x7a, 0x08, 0x1a, 0x77,
        0xde, 0x20, 0x09, 0xd1, 0x40, 0x2e, 0x6e, 0x03,
      ]
    end

    it "should encrypt case 2 in ECB mode" do
      # Tests multiple blocks
      u = AES::Utils.new(192, AES::Mode::ECB)
      plaintext = [
        0x67, 0x3d, 0x3c, 0xd6, 0xb8, 0x28, 0x0f, 0xe1,
        0x95, 0x2e, 0xae, 0xfa, 0x94, 0xa0, 0x02, 0x5d,
        0x30, 0x66, 0x95, 0xb3, 0x9d, 0x89, 0x4d, 0xb4,
        0x64, 0xe7, 0x62, 0x03, 0x66, 0xfb, 0x78, 0x20,
      ]
      key = [
        0x51, 0xe5, 0xa1, 0x2c, 0xd2, 0xd3, 0x0c, 0xaa,
        0xf5, 0x31, 0xd6, 0xcc, 0xbe, 0xbe, 0x1a, 0x03,
        0x29, 0x73, 0x0b, 0xe0, 0xdf, 0x11, 0xc0, 0x3c,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0x9e, 0x28, 0x0d, 0xc6, 0x37, 0x39, 0x39, 0x9b,
        0x47, 0x12, 0x1f, 0x1f, 0x49, 0x66, 0xd4, 0xd0,
        0x91, 0xb7, 0xb8, 0xcb, 0xac, 0xd5, 0xed, 0x62,
        0xcc, 0x21, 0x04, 0x9b, 0xf1, 0x29, 0xc4, 0x9f,
      ]
    end

    it "should encrypt case 2 in CBC mode" do
      # Tests multiple blocks
      u = AES::Utils.new(192, AES::Mode::CBC)
      plaintext = [
        0x67, 0x3d, 0x3c, 0xd6, 0xb8, 0x28, 0x0f, 0xe1,
        0x95, 0x2e, 0xae, 0xfa, 0x94, 0xa0, 0x02, 0x5d,
        0x30, 0x66, 0x95, 0xb3, 0x9d, 0x89, 0x4d, 0xb4,
        0x64, 0xe7, 0x62, 0x03, 0x66, 0xfb, 0x78, 0x20,
      ]
      key = [
        0x51, 0xe5, 0xa1, 0x2c, 0xd2, 0xd3, 0x0c, 0xaa,
        0xf5, 0x31, 0xd6, 0xcc, 0xbe, 0xbe, 0x1a, 0x03,
        0x29, 0x73, 0x0b, 0xe0, 0xdf, 0x11, 0xc0, 0x3c,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0x9e, 0x28, 0x0d, 0xc6, 0x37, 0x39, 0x39, 0x9b,
        0x47, 0x12, 0x1f, 0x1f, 0x49, 0x66, 0xd4, 0xd0,
        0xbf, 0x22, 0x8b, 0xd5, 0xa8, 0xf5, 0x32, 0xa6,
        0x3c, 0xe5, 0x4e, 0xab, 0x20, 0xc5, 0x72, 0x12,
      ]
    end

    it "should encrypt case 3 in ECB mode" do
      u = AES::Utils.new(256, AES::Mode::ECB)
      plaintext = [
        0xed, 0x20, 0x30, 0xdb, 0x7e, 0x1f, 0x1a, 0x77,
        0x2c, 0xc9, 0x0c, 0xea, 0x95, 0xbf, 0xcd, 0x0b,
        0x05, 0x1a, 0x1a, 0x02, 0x9b, 0xf4, 0x2b, 0x99,
        0xb1, 0x05, 0x55, 0x1c, 0x5f, 0xb5, 0xd3, 0x5b,
        0x82, 0xee, 0x48, 0x7f, 0x83, 0x2f, 0x12, 0x31,
        0x40, 0x85, 0x8d, 0x9f, 0xdb, 0x98, 0x55, 0x02,
      ]
      key = [
        0x69, 0x8d, 0x0e, 0xe2, 0xe3, 0x3b, 0x86, 0xfd,
        0x7a, 0xcb, 0x38, 0xd2, 0x00, 0x6f, 0xb2, 0xdb,
        0xd7, 0xee, 0x32, 0xf4, 0x7f, 0x11, 0x84, 0xb7,
        0x26, 0xd6, 0x5a, 0x0b, 0xc5, 0x8a, 0xfc, 0x40,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0xe4, 0x51, 0x83, 0xee, 0xa6, 0x2d, 0x1e, 0xdd,
        0xc5, 0x14, 0x8a, 0x63, 0xe0, 0x0b, 0x08, 0xb2,
        0x84, 0x84, 0x90, 0xa1, 0x78, 0x35, 0x15, 0xfa,
        0x6a, 0x22, 0xb1, 0x7e, 0xb3, 0x35, 0x0e, 0x67,
        0xe2, 0x30, 0x10, 0x8d, 0x01, 0x76, 0x42, 0x91,
        0x35, 0x9b, 0xa6, 0xb2, 0x47, 0x78, 0xb7, 0x07,
      ]
    end

    it "should encrypt case 3 in CBC mode" do
      u = AES::Utils.new(256, AES::Mode::CBC)
      plaintext = [
        0xed, 0x20, 0x30, 0xdb, 0x7e, 0x1f, 0x1a, 0x77,
        0x2c, 0xc9, 0x0c, 0xea, 0x95, 0xbf, 0xcd, 0x0b,
        0x05, 0x1a, 0x1a, 0x02, 0x9b, 0xf4, 0x2b, 0x99,
        0xb1, 0x05, 0x55, 0x1c, 0x5f, 0xb5, 0xd3, 0x5b,
        0x82, 0xee, 0x48, 0x7f, 0x83, 0x2f, 0x12, 0x31,
        0x40, 0x85, 0x8d, 0x9f, 0xdb, 0x98, 0x55, 0x02,
      ]
      key = [
        0x69, 0x8d, 0x0e, 0xe2, 0xe3, 0x3b, 0x86, 0xfd,
        0x7a, 0xcb, 0x38, 0xd2, 0x00, 0x6f, 0xb2, 0xdb,
        0xd7, 0xee, 0x32, 0xf4, 0x7f, 0x11, 0x84, 0xb7,
        0x26, 0xd6, 0x5a, 0x0b, 0xc5, 0x8a, 0xfc, 0x40,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0xe4, 0x51, 0x83, 0xee, 0xa6, 0x2d, 0x1e, 0xdd,
        0xc5, 0x14, 0x8a, 0x63, 0xe0, 0x0b, 0x08, 0xb2,
        0xe5, 0x12, 0xfe, 0x8d, 0xa8, 0x71, 0x08, 0xde,
        0xf2, 0x7e, 0xed, 0x8c, 0x54, 0xec, 0x20, 0x25,
        0xad, 0x84, 0x9c, 0x10, 0x1c, 0x3a, 0xfe, 0x1f,
        0xf7, 0x3c, 0xdb, 0x2a, 0x43, 0x35, 0xba, 0x04,
      ]
    end

    it "should encrypt case 4 in ECB mode" do
      u = AES::Utils.new(128, AES::Mode::ECB)
      plaintext = [
        0x08, 0xd8, 0x02, 0x75, 0x53, 0x76, 0x9e, 0x81,
        0xc7, 0x41, 0x57, 0x98, 0xa3, 0x0f, 0x1d, 0x82,
        0x4c, 0x12, 0x85, 0x3f, 0x04, 0x35, 0x21, 0x69,
        0x62, 0x32, 0xaf, 0x4b, 0xd1, 0x86, 0x9e, 0x83,
        0x97, 0xd3, 0xfc, 0x36, 0xdd, 0x7d, 0xc6, 0xf7,
        0xa5, 0xfa, 0xcb, 0xba, 0xbf, 0xea, 0xdc, 0x67,
        0x89, 0x11, 0xa4, 0xf6, 0xca, 0x29, 0xd4, 0x19,
        0x65, 0xeb, 0x20, 0x64, 0x4d, 0x4b, 0x28, 0x90,
      ]
      key = [
        0x2e, 0x65, 0x1e, 0x1f, 0x82, 0x04, 0x60, 0x69,
        0xb0, 0xc0, 0x87, 0xa2, 0xc5, 0xa4, 0x3f, 0xd5,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0x4d, 0x5a, 0x64, 0xe1, 0xab, 0x11, 0xc8, 0xb8,
        0x5d, 0x40, 0x9a, 0x65, 0xb8, 0x6c, 0xa2, 0x6b,
        0x60, 0xaa, 0xa3, 0x1c, 0xf5, 0x20, 0x76, 0xca,
        0x8b, 0x57, 0x4a, 0xf7, 0x54, 0xd2, 0x90, 0x1f,
        0x22, 0x4f, 0xc4, 0x31, 0xd8, 0x5e, 0x0c, 0x00,
        0xd0, 0x3d, 0xb6, 0x15, 0x02, 0x59, 0xb1, 0xcb,
        0xb0, 0xc6, 0x13, 0x8e, 0x15, 0x45, 0x59, 0x63,
        0xb6, 0xf6, 0xf9, 0xba, 0x8c, 0xa3, 0x7b, 0x2f,
      ]
    end

    it "should encrypt case 4 in CBC mode" do
      u = AES::Utils.new(128, AES::Mode::CBC)
      plaintext = [
        0x08, 0xd8, 0x02, 0x75, 0x53, 0x76, 0x9e, 0x81,
        0xc7, 0x41, 0x57, 0x98, 0xa3, 0x0f, 0x1d, 0x82,
        0x4c, 0x12, 0x85, 0x3f, 0x04, 0x35, 0x21, 0x69,
        0x62, 0x32, 0xaf, 0x4b, 0xd1, 0x86, 0x9e, 0x83,
        0x97, 0xd3, 0xfc, 0x36, 0xdd, 0x7d, 0xc6, 0xf7,
        0xa5, 0xfa, 0xcb, 0xba, 0xbf, 0xea, 0xdc, 0x67,
        0x89, 0x11, 0xa4, 0xf6, 0xca, 0x29, 0xd4, 0x19,
        0x65, 0xeb, 0x20, 0x64, 0x4d, 0x4b, 0x28, 0x90,
      ]
      key = [
        0x2e, 0x65, 0x1e, 0x1f, 0x82, 0x04, 0x60, 0x69,
        0xb0, 0xc0, 0x87, 0xa2, 0xc5, 0xa4, 0x3f, 0xd5,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0x4d, 0x5a, 0x64, 0xe1, 0xab, 0x11, 0xc8, 0xb8,
        0x5d, 0x40, 0x9a, 0x65, 0xb8, 0x6c, 0xa2, 0x6b,
        0x64, 0xa3, 0x3c, 0x04, 0xb4, 0x55, 0x05, 0xf2,
        0xdb, 0x5c, 0x5d, 0xc7, 0xea, 0x33, 0x87, 0x41,
        0x41, 0x1e, 0x5a, 0x7a, 0x51, 0x4f, 0xf2, 0xa2,
        0x36, 0x84, 0xa0, 0xad, 0x0d, 0x12, 0xd5, 0x5e,
        0x46, 0x39, 0x11, 0x8b, 0x69, 0xbe, 0x2c, 0xff,
        0x7a, 0x3c, 0xc5, 0x8a, 0x8b, 0xb6, 0x46, 0x83,
      ]
    end

    it "should encrypt case 5 in ECB mode" do
      u = AES::Utils.new(192, AES::Mode::ECB)
      plaintext = [
        0x2f, 0x8c, 0xd6, 0xbb, 0x66, 0xe6, 0x1b, 0x7a,
        0x3a, 0x36, 0xef, 0x78, 0x0e, 0x3f, 0xa4, 0xe7,
        0x35, 0x28, 0x5c, 0x10, 0xe1, 0xe7, 0xfe, 0xef,
        0x37, 0x22, 0xf7, 0x26, 0x27, 0x1d, 0xab, 0xdc,
        0x95, 0x7b, 0x7a, 0x3d, 0x1a, 0x8f, 0xfa, 0x51,
        0xe8, 0x4e, 0x30, 0x95, 0xe7, 0x05, 0x7c, 0xab,
        0x3b, 0xfa, 0x61, 0xe9, 0xf9, 0x4e, 0x33, 0xc1,
        0xeb, 0xa2, 0x17, 0x52, 0xf6, 0x6f, 0xca, 0x03,
        0xfd, 0x5e, 0xfe, 0xb1, 0x2a, 0xb3, 0x47, 0x3e,
        0x7f, 0xe3, 0x27, 0xe6, 0xfb, 0x52, 0xa3, 0x8f,
      ]
      key = [
        0xf4, 0xa7, 0x13, 0xa6, 0x6f, 0x78, 0x24, 0xe0,
        0xe0, 0x12, 0x85, 0xb1, 0xff, 0x23, 0x99, 0x0b,
        0x11, 0xb5, 0xde, 0x4e, 0xa0, 0x1c, 0x11, 0xac,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0xa4, 0x7c, 0x9a, 0x1f, 0xaa, 0x57, 0x5e, 0x85,
        0xa0, 0xc6, 0x1c, 0x9f, 0x77, 0x35, 0xc0, 0x59,
        0x84, 0x4e, 0x0c, 0x69, 0x1f, 0xa5, 0x32, 0x38,
        0xc8, 0xc1, 0xec, 0x62, 0x75, 0xe0, 0xa9, 0x0e,
        0xba, 0x39, 0x27, 0xe5, 0xa8, 0x9f, 0x09, 0x63,
        0x97, 0xdf, 0x65, 0xe2, 0xea, 0x9b, 0x91, 0x50,
        0xeb, 0x30, 0xfe, 0xe7, 0x5b, 0x8b, 0xcf, 0x8d,
        0x80, 0x0e, 0x13, 0xb6, 0x2c, 0x55, 0xb7, 0x01,
        0x5a, 0x59, 0x7e, 0xfb, 0x6c, 0x14, 0xb1, 0x4e,
        0x62, 0x04, 0x07, 0xe6, 0x86, 0x7e, 0x2a, 0xa2,
      ]
    end

    it "should encrypt case 5 in CBC mode" do
      u = AES::Utils.new(192, AES::Mode::CBC)
      plaintext = [
        0x2f, 0x8c, 0xd6, 0xbb, 0x66, 0xe6, 0x1b, 0x7a,
        0x3a, 0x36, 0xef, 0x78, 0x0e, 0x3f, 0xa4, 0xe7,
        0x35, 0x28, 0x5c, 0x10, 0xe1, 0xe7, 0xfe, 0xef,
        0x37, 0x22, 0xf7, 0x26, 0x27, 0x1d, 0xab, 0xdc,
        0x95, 0x7b, 0x7a, 0x3d, 0x1a, 0x8f, 0xfa, 0x51,
        0xe8, 0x4e, 0x30, 0x95, 0xe7, 0x05, 0x7c, 0xab,
        0x3b, 0xfa, 0x61, 0xe9, 0xf9, 0x4e, 0x33, 0xc1,
        0xeb, 0xa2, 0x17, 0x52, 0xf6, 0x6f, 0xca, 0x03,
        0xfd, 0x5e, 0xfe, 0xb1, 0x2a, 0xb3, 0x47, 0x3e,
        0x7f, 0xe3, 0x27, 0xe6, 0xfb, 0x52, 0xa3, 0x8f,
      ]
      key = [
        0xf4, 0xa7, 0x13, 0xa6, 0x6f, 0x78, 0x24, 0xe0,
        0xe0, 0x12, 0x85, 0xb1, 0xff, 0x23, 0x99, 0x0b,
        0x11, 0xb5, 0xde, 0x4e, 0xa0, 0x1c, 0x11, 0xac,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0xa4, 0x7c, 0x9a, 0x1f, 0xaa, 0x57, 0x5e, 0x85,
        0xa0, 0xc6, 0x1c, 0x9f, 0x77, 0x35, 0xc0, 0x59,
        0x67, 0x41, 0x65, 0x37, 0x83, 0x27, 0x67, 0x17,
        0x4f, 0x1c, 0x7b, 0x63, 0x2e, 0x9e, 0xbd, 0x5c,
        0xa4, 0x01, 0xd5, 0x0a, 0x23, 0x27, 0xed, 0x0e,
        0x9b, 0xd8, 0x41, 0xed, 0xe1, 0x65, 0x8e, 0x91,
        0x36, 0xcf, 0x8c, 0xde, 0x8b, 0xc3, 0x96, 0x41,
        0x22, 0xf7, 0xfa, 0x5d, 0x4e, 0x6b, 0xa9, 0xed,
        0x55, 0x11, 0x61, 0x55, 0x58, 0x2e, 0x2a, 0xe5,
        0x3c, 0x2f, 0x5e, 0xf8, 0x1a, 0x2e, 0xdd, 0x67,
      ]
    end

    it "should encrypt case 6 in ECB mode" do
      u = AES::Utils.new(256, AES::Mode::ECB)
      plaintext = [
        0x2d, 0xb7, 0x1d, 0x70, 0x24, 0xbe, 0xb0, 0xaf,
        0x48, 0x03, 0xc1, 0xad, 0xb8, 0xc8, 0x09, 0x03,
        0xe5, 0xc7, 0x0d, 0x65, 0xdb, 0x25, 0x18, 0x76,
        0x14, 0x2d, 0x44, 0xda, 0x37, 0xb0, 0x72, 0x23,
        0x51, 0xd0, 0x8d, 0x21, 0xe4, 0xe0, 0xe2, 0xf0,
        0xcf, 0xfe, 0x0a, 0xcd, 0x42, 0x2b, 0x5e, 0x49,
        0x75, 0xd6, 0xb4, 0x72, 0x0e, 0xdb, 0x47, 0x16,
        0xb3, 0xaf, 0x33, 0x87, 0x69, 0x27, 0xa9, 0xee,
        0x7f, 0x25, 0xa2, 0x66, 0x37, 0x8c, 0x05, 0xc4,
        0x21, 0x6e, 0x54, 0xf9, 0xee, 0x0d, 0xef, 0x21,
        0x7a, 0x70, 0xbd, 0x30, 0xe5, 0xdb, 0xd3, 0x6e,
        0x9a, 0xeb, 0xbc, 0xbd, 0x17, 0x7e, 0xb4, 0x46,
      ]
      key = [
        0xd5, 0x11, 0x45, 0xf9, 0xa2, 0x3c, 0xd0, 0x0f,
        0x9d, 0xf7, 0x59, 0x1a, 0xc4, 0x8e, 0x3b, 0xfe,
        0x46, 0xa1, 0x8c, 0x9c, 0xf5, 0x0a, 0xd9, 0x85,
        0x88, 0x1d, 0x98, 0x1b, 0x3e, 0x99, 0xe6, 0xd0,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0x57, 0x2b, 0x50, 0x2e, 0xc1, 0x28, 0xb9, 0x66,
        0xd5, 0xf5, 0x9a, 0x1c, 0x21, 0xa2, 0x31, 0xd6,
        0xa6, 0x90, 0x99, 0x30, 0xfa, 0x3d, 0x48, 0x3c,
        0x73, 0x5b, 0x87, 0x67, 0x60, 0x07, 0x5b, 0x2a,
        0x1e, 0xbe, 0xb8, 0x56, 0x10, 0xa4, 0x95, 0x7b,
        0x20, 0xf0, 0xeb, 0x1b, 0x93, 0xbb, 0xfc, 0xa8,
        0xcf, 0x15, 0x34, 0x17, 0x34, 0xf6, 0x6b, 0xcf,
        0x3d, 0x71, 0x64, 0x88, 0x04, 0x21, 0x99, 0xaa,
        0x0b, 0xaf, 0xca, 0x10, 0x7b, 0xa4, 0x22, 0xf1,
        0xeb, 0x26, 0x6e, 0x8e, 0x15, 0xd1, 0xf1, 0x34,
        0x14, 0x9b, 0xcd, 0x42, 0x3d, 0x1c, 0x92, 0x6c,
        0x98, 0xc9, 0xf4, 0xae, 0xdd, 0xf8, 0x67, 0x4a,
      ]
    end

    it "should encrypt case 6 in CBC mode" do
      u = AES::Utils.new(256, AES::Mode::CBC)
      plaintext = [
        0x2d, 0xb7, 0x1d, 0x70, 0x24, 0xbe, 0xb0, 0xaf,
        0x48, 0x03, 0xc1, 0xad, 0xb8, 0xc8, 0x09, 0x03,
        0xe5, 0xc7, 0x0d, 0x65, 0xdb, 0x25, 0x18, 0x76,
        0x14, 0x2d, 0x44, 0xda, 0x37, 0xb0, 0x72, 0x23,
        0x51, 0xd0, 0x8d, 0x21, 0xe4, 0xe0, 0xe2, 0xf0,
        0xcf, 0xfe, 0x0a, 0xcd, 0x42, 0x2b, 0x5e, 0x49,
        0x75, 0xd6, 0xb4, 0x72, 0x0e, 0xdb, 0x47, 0x16,
        0xb3, 0xaf, 0x33, 0x87, 0x69, 0x27, 0xa9, 0xee,
        0x7f, 0x25, 0xa2, 0x66, 0x37, 0x8c, 0x05, 0xc4,
        0x21, 0x6e, 0x54, 0xf9, 0xee, 0x0d, 0xef, 0x21,
        0x7a, 0x70, 0xbd, 0x30, 0xe5, 0xdb, 0xd3, 0x6e,
        0x9a, 0xeb, 0xbc, 0xbd, 0x17, 0x7e, 0xb4, 0x46,
      ]
      key = [
        0xd5, 0x11, 0x45, 0xf9, 0xa2, 0x3c, 0xd0, 0x0f,
        0x9d, 0xf7, 0x59, 0x1a, 0xc4, 0x8e, 0x3b, 0xfe,
        0x46, 0xa1, 0x8c, 0x9c, 0xf5, 0x0a, 0xd9, 0x85,
        0x88, 0x1d, 0x98, 0x1b, 0x3e, 0x99, 0xe6, 0xd0,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0x57, 0x2b, 0x50, 0x2e, 0xc1, 0x28, 0xb9, 0x66,
        0xd5, 0xf5, 0x9a, 0x1c, 0x21, 0xa2, 0x31, 0xd6,
        0x87, 0x17, 0x7f, 0xf4, 0xf9, 0x8e, 0x10, 0x95,
        0x04, 0xbb, 0x63, 0x7d, 0x16, 0xd5, 0x1a, 0xdf,
        0xb4, 0x4a, 0x5f, 0xce, 0x44, 0xee, 0x9d, 0x0e,
        0x10, 0xd1, 0x48, 0x23, 0x52, 0xc4, 0x2b, 0x99,
        0xff, 0xac, 0xc2, 0xf4, 0xb8, 0x16, 0x81, 0x9b,
        0x11, 0xfe, 0xe5, 0xb0, 0xf9, 0x12, 0xdf, 0x27,
        0x8e, 0xfb, 0x3a, 0xd2, 0xc2, 0x4a, 0xd8, 0xd2,
        0xad, 0x05, 0x87, 0x13, 0x39, 0x2c, 0xee, 0x67,
        0xb7, 0xa4, 0x89, 0x1e, 0x39, 0x91, 0x11, 0xd8,
        0xaf, 0xa0, 0xff, 0xa2, 0x57, 0x97, 0xc8, 0x91,
      ]
    end

    it "should encrypt case 7 in ECB mode" do
      u = AES::Utils.new(128, AES::Mode::ECB)
      plaintext = [
        0x60, 0xdc, 0x19, 0xd2, 0xc6, 0x88, 0x70, 0xee,
        0x0b, 0x4a, 0x9b, 0x57, 0x0e, 0xce, 0x5a, 0xe5,
        0x2d, 0x00, 0x23, 0xe8, 0x9c, 0x5d, 0xd6, 0x4e,
        0xdb, 0x1b, 0x01, 0x01, 0x34, 0xd3, 0xb9, 0xa1,
        0x6d, 0xb3, 0xd1, 0x3c, 0x58, 0x02, 0x82, 0xe8,
        0x36, 0x48, 0xee, 0x39, 0xc7, 0x1a, 0x31, 0xdd,
        0x4f, 0xad, 0x18, 0x49, 0x99, 0x26, 0x97, 0x3f,
        0x91, 0xea, 0xb1, 0x74, 0x51, 0x6b, 0x84, 0xce,
        0xdd, 0x42, 0xcf, 0xe8, 0x4f, 0x61, 0x0d, 0x14,
        0xfa, 0xa7, 0x3d, 0xaf, 0x63, 0x7d, 0xbe, 0x8e,
        0x66, 0x41, 0x6f, 0x14, 0xa7, 0xa6, 0x1a, 0x85,
        0xf8, 0xc4, 0x98, 0xbf, 0xb4, 0x80, 0xb8, 0x6f,
        0x89, 0xf4, 0xd4, 0x45, 0xbc, 0x8b, 0x92, 0x0b,
        0xfd, 0x3a, 0x22, 0xd4, 0xc9, 0xbb, 0x73, 0x9c,
      ]
      key = [
        0x26, 0xcf, 0x06, 0x7f, 0x54, 0xcf, 0xe2, 0x3e,
        0x35, 0x0d, 0x6a, 0x75, 0xb4, 0x22, 0xaa, 0x10,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0x8d, 0x00, 0x7c, 0xbc, 0x64, 0xca, 0xb7, 0x65,
        0xdc, 0xa0, 0x80, 0xf8, 0xad, 0x73, 0xae, 0xf4,
        0xb1, 0x30, 0x9a, 0x39, 0xdc, 0xce, 0x87, 0xb2,
        0x17, 0x93, 0x8d, 0xfa, 0x08, 0x3f, 0x8f, 0xd9,
        0xc4, 0x8f, 0xb8, 0xeb, 0x74, 0x4c, 0x94, 0x5a,
        0xf0, 0x09, 0x55, 0x81, 0xb4, 0x2f, 0x6d, 0x2a,
        0x10, 0x44, 0x4a, 0xe0, 0x3e, 0xea, 0x15, 0xd7,
        0x8c, 0x65, 0x72, 0x4b, 0xcc, 0x31, 0x64, 0xd0,
        0x83, 0x43, 0x49, 0xc1, 0xaf, 0x8d, 0x28, 0xf9,
        0x67, 0x37, 0xbc, 0x6f, 0x70, 0xa5, 0x1d, 0xa4,
        0xcb, 0xb6, 0x9b, 0x35, 0xe4, 0xc4, 0x68, 0x6f,
        0x98, 0xd8, 0x94, 0x28, 0xae, 0x7d, 0x11, 0xe4,
        0x6d, 0x4d, 0x91, 0xe4, 0xac, 0xdb, 0xe9, 0x05,
        0x42, 0xeb, 0xfb, 0xf4, 0x6f, 0xe7, 0x53, 0xa7,
      ]
    end

    it "should encrypt case 7 in CBC mode" do
      u = AES::Utils.new(128, AES::Mode::CBC)
      plaintext = [
        0x60, 0xdc, 0x19, 0xd2, 0xc6, 0x88, 0x70, 0xee,
        0x0b, 0x4a, 0x9b, 0x57, 0x0e, 0xce, 0x5a, 0xe5,
        0x2d, 0x00, 0x23, 0xe8, 0x9c, 0x5d, 0xd6, 0x4e,
        0xdb, 0x1b, 0x01, 0x01, 0x34, 0xd3, 0xb9, 0xa1,
        0x6d, 0xb3, 0xd1, 0x3c, 0x58, 0x02, 0x82, 0xe8,
        0x36, 0x48, 0xee, 0x39, 0xc7, 0x1a, 0x31, 0xdd,
        0x4f, 0xad, 0x18, 0x49, 0x99, 0x26, 0x97, 0x3f,
        0x91, 0xea, 0xb1, 0x74, 0x51, 0x6b, 0x84, 0xce,
        0xdd, 0x42, 0xcf, 0xe8, 0x4f, 0x61, 0x0d, 0x14,
        0xfa, 0xa7, 0x3d, 0xaf, 0x63, 0x7d, 0xbe, 0x8e,
        0x66, 0x41, 0x6f, 0x14, 0xa7, 0xa6, 0x1a, 0x85,
        0xf8, 0xc4, 0x98, 0xbf, 0xb4, 0x80, 0xb8, 0x6f,
        0x89, 0xf4, 0xd4, 0x45, 0xbc, 0x8b, 0x92, 0x0b,
        0xfd, 0x3a, 0x22, 0xd4, 0xc9, 0xbb, 0x73, 0x9c,
      ]
      key = [
        0x26, 0xcf, 0x06, 0x7f, 0x54, 0xcf, 0xe2, 0x3e,
        0x35, 0x0d, 0x6a, 0x75, 0xb4, 0x22, 0xaa, 0x10,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0x8d, 0x00, 0x7c, 0xbc, 0x64, 0xca, 0xb7, 0x65,
        0xdc, 0xa0, 0x80, 0xf8, 0xad, 0x73, 0xae, 0xf4,
        0x17, 0x71, 0x30, 0x6c, 0x9c, 0xd1, 0x80, 0x05,
        0x6c, 0x28, 0x03, 0x9e, 0x52, 0xa2, 0x27, 0x64,
        0xf5, 0x6a, 0x51, 0x8a, 0x06, 0x1d, 0xfe, 0xfe,
        0xcf, 0x7c, 0xbc, 0x3a, 0xe0, 0xaf, 0x8c, 0xcf,
        0x1b, 0x1c, 0x54, 0x9b, 0xba, 0x66, 0x0c, 0xd0,
        0x3e, 0x55, 0x30, 0x73, 0xd5, 0x68, 0xa2, 0xc4,
        0xac, 0x29, 0x06, 0xfd, 0x5d, 0x6c, 0xeb, 0xc6,
        0x30, 0xa8, 0x5e, 0x81, 0xc9, 0xe1, 0x63, 0x68,
        0x9f, 0x7f, 0x96, 0x0e, 0x7e, 0xc2, 0xe2, 0xd0,
        0x6b, 0xd8, 0x53, 0x84, 0x2a, 0xc9, 0x3b, 0x6c,
        0xf8, 0x9c, 0x71, 0xd3, 0x3e, 0xe7, 0x94, 0xde,
        0x79, 0x82, 0xe9, 0x45, 0x10, 0x79, 0x02, 0x21,
      ]
    end

    it "should encrypt case 8 in ECB mode" do
      u = AES::Utils.new(192, AES::Mode::ECB)
      plaintext = [
        0x08, 0x62, 0x76, 0x0c, 0x67, 0xa0, 0xcd, 0xc3,
        0xed, 0xe7, 0x79, 0xb9, 0xec, 0xa0, 0x08, 0x37,
        0xd5, 0xf0, 0x54, 0xda, 0x8a, 0xfb, 0x58, 0x8b,
        0xce, 0x10, 0x33, 0x37, 0x3d, 0xd9, 0x15, 0x48,
        0x68, 0xff, 0xe1, 0x1c, 0x43, 0x38, 0xa2, 0x8a,
        0x91, 0x4a, 0x83, 0x4c, 0x43, 0xd7, 0x81, 0xad,
        0xda, 0xd9, 0xac, 0x8a, 0x40, 0xa3, 0xaa, 0x9a,
        0x8f, 0xf4, 0xa9, 0xca, 0x71, 0xb8, 0x76, 0x27,
        0xad, 0x84, 0x0e, 0x86, 0xdf, 0xc3, 0x3b, 0x28,
        0xd0, 0x6d, 0x6e, 0xca, 0x44, 0x0d, 0x34, 0x59,
        0x86, 0x88, 0x5a, 0xfc, 0x85, 0x20, 0x7c, 0x8a,
        0xcf, 0x6b, 0x0b, 0x79, 0x7e, 0xa8, 0xa4, 0xfc,
        0x49, 0x79, 0xea, 0xac, 0xb4, 0x3f, 0x80, 0x81,
        0xa9, 0x07, 0x85, 0x67, 0x65, 0xb6, 0x15, 0x1d,
        0x06, 0x5a, 0x1d, 0x96, 0xe0, 0x12, 0x1f, 0xf4,
        0x61, 0x07, 0x24, 0x0b, 0x1d, 0x89, 0x19, 0x9a,
      ]
      key = [
        0xa5, 0x49, 0x54, 0x95, 0xd0, 0xb6, 0x17, 0x41,
        0xfa, 0x67, 0x4a, 0x77, 0xfd, 0x7a, 0xc2, 0x31,
        0xe8, 0xd1, 0x0b, 0x68, 0x19, 0xdb, 0x40, 0xe1,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0x1c, 0x47, 0xec, 0xad, 0xae, 0xf8, 0x96, 0x48,
        0x08, 0x5c, 0xdb, 0x40, 0x94, 0x9f, 0x5f, 0xc9,
        0x47, 0x77, 0x4d, 0xa8, 0xa3, 0xee, 0x4f, 0x88,
        0x1f, 0x51, 0x64, 0xdf, 0xb0, 0x45, 0x41, 0xde,
        0x3b, 0x8b, 0xe0, 0xb2, 0xaa, 0x15, 0x5b, 0x15,
        0xf7, 0x1f, 0x0a, 0x9c, 0xce, 0xc1, 0xf7, 0x16,
        0x7c, 0x8e, 0x58, 0x66, 0x96, 0x8c, 0x22, 0xfa,
        0x19, 0xc6, 0x58, 0xda, 0x98, 0xf4, 0xf7, 0x3b,
        0xb9, 0xf1, 0x36, 0xa6, 0x3e, 0x7b, 0x70, 0x85,
        0xcd, 0x86, 0xe8, 0xcc, 0xbe, 0x15, 0xcb, 0x7e,
        0x48, 0xba, 0x3f, 0x74, 0x91, 0xc6, 0x7a, 0xc6,
        0x57, 0x44, 0xe4, 0x26, 0x4b, 0xd6, 0x59, 0xc4,
        0x1a, 0xed, 0xf3, 0xa1, 0xf5, 0xde, 0xb9, 0xf0,
        0x75, 0x57, 0xd6, 0x9e, 0xa7, 0xdf, 0x74, 0xc3,
        0x1b, 0x61, 0x73, 0x14, 0x43, 0xcf, 0x0b, 0x89,
        0xdf, 0x41, 0xb4, 0x54, 0x72, 0x01, 0x95, 0xe8,
      ]
    end

    it "should encrypt case 8 in CBC mode" do
      u = AES::Utils.new(192, AES::Mode::CBC)
      plaintext = [
        0x08, 0x62, 0x76, 0x0c, 0x67, 0xa0, 0xcd, 0xc3,
        0xed, 0xe7, 0x79, 0xb9, 0xec, 0xa0, 0x08, 0x37,
        0xd5, 0xf0, 0x54, 0xda, 0x8a, 0xfb, 0x58, 0x8b,
        0xce, 0x10, 0x33, 0x37, 0x3d, 0xd9, 0x15, 0x48,
        0x68, 0xff, 0xe1, 0x1c, 0x43, 0x38, 0xa2, 0x8a,
        0x91, 0x4a, 0x83, 0x4c, 0x43, 0xd7, 0x81, 0xad,
        0xda, 0xd9, 0xac, 0x8a, 0x40, 0xa3, 0xaa, 0x9a,
        0x8f, 0xf4, 0xa9, 0xca, 0x71, 0xb8, 0x76, 0x27,
        0xad, 0x84, 0x0e, 0x86, 0xdf, 0xc3, 0x3b, 0x28,
        0xd0, 0x6d, 0x6e, 0xca, 0x44, 0x0d, 0x34, 0x59,
        0x86, 0x88, 0x5a, 0xfc, 0x85, 0x20, 0x7c, 0x8a,
        0xcf, 0x6b, 0x0b, 0x79, 0x7e, 0xa8, 0xa4, 0xfc,
        0x49, 0x79, 0xea, 0xac, 0xb4, 0x3f, 0x80, 0x81,
        0xa9, 0x07, 0x85, 0x67, 0x65, 0xb6, 0x15, 0x1d,
        0x06, 0x5a, 0x1d, 0x96, 0xe0, 0x12, 0x1f, 0xf4,
        0x61, 0x07, 0x24, 0x0b, 0x1d, 0x89, 0x19, 0x9a,
      ]
      key = [
        0xa5, 0x49, 0x54, 0x95, 0xd0, 0xb6, 0x17, 0x41,
        0xfa, 0x67, 0x4a, 0x77, 0xfd, 0x7a, 0xc2, 0x31,
        0xe8, 0xd1, 0x0b, 0x68, 0x19, 0xdb, 0x40, 0xe1,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0x1c, 0x47, 0xec, 0xad, 0xae, 0xf8, 0x96, 0x48,
        0x08, 0x5c, 0xdb, 0x40, 0x94, 0x9f, 0x5f, 0xc9,
        0x01, 0x1e, 0xad, 0xff, 0x1d, 0x9d, 0xbe, 0xfe,
        0xa1, 0xca, 0x6c, 0x82, 0xc9, 0x36, 0x40, 0x04,
        0x06, 0x14, 0xd2, 0xa8, 0x4e, 0x51, 0x2c, 0x4a,
        0x21, 0x3e, 0xc5, 0xb6, 0xc7, 0xd2, 0x98, 0x34,
        0xc0, 0x76, 0x2a, 0x0d, 0xaa, 0x22, 0x29, 0x8e,
        0x3c, 0xb0, 0x62, 0x82, 0x8f, 0x15, 0x5f, 0x8b,
        0x7d, 0x46, 0x78, 0xf4, 0xba, 0xc3, 0xe3, 0x68,
        0x8e, 0xe4, 0x20, 0xb4, 0x86, 0xfb, 0xaa, 0x1c,
        0xda, 0x87, 0xac, 0x81, 0x1c, 0x62, 0xe4, 0xad,
        0x16, 0x13, 0x22, 0x2c, 0x6a, 0xda, 0x8d, 0xdc,
        0x86, 0x1a, 0x6f, 0x10, 0xfa, 0xae, 0xcc, 0x3f,
        0x14, 0xcd, 0x82, 0x71, 0xdd, 0x66, 0xdd, 0xb2,
        0x20, 0xac, 0x0f, 0xda, 0x50, 0xf4, 0x70, 0x50,
        0xca, 0xc2, 0x2b, 0xd8, 0x29, 0xdf, 0x6d, 0x0d,
      ]
    end

    it "should encrypt case 9 in ECB mode" do
      u = AES::Utils.new(256, AES::Mode::ECB)
      plaintext = [
        0x45, 0xb7, 0xcf, 0x11, 0x83, 0x95, 0x38, 0xda,
        0x7d, 0xa1, 0xca, 0x40, 0xc3, 0xf4, 0xb9, 0x24,
        0xa3, 0xf6, 0xac, 0xa5, 0x3d, 0x3d, 0x49, 0x6f,
        0x4f, 0x93, 0x5f, 0xf6, 0x8a, 0xd8, 0xe5, 0x4d,
        0x69, 0xe4, 0x85, 0x1f, 0xdc, 0x21, 0xcd, 0xfd,
        0x62, 0xa0, 0x53, 0xa2, 0xea, 0xaa, 0x82, 0x9d,
        0x14, 0xde, 0x2a, 0x05, 0x7f, 0xde, 0x14, 0x44,
        0xed, 0xac, 0x8f, 0xdf, 0xb5, 0x95, 0x29, 0x11,
        0x30, 0x73, 0x92, 0x7e, 0x19, 0x37, 0xe6, 0x54,
        0x36, 0x0b, 0x21, 0xf5, 0x9a, 0xb7, 0xdd, 0xde,
        0xad, 0xc2, 0x36, 0x05, 0x5e, 0x7b, 0x47, 0xcd,
        0x08, 0x9a, 0xfe, 0xf3, 0x6f, 0x7b, 0x73, 0x12,
        0x25, 0x67, 0xe2, 0x59, 0x27, 0x19, 0x7a, 0x4c,
        0x06, 0x8c, 0x7d, 0x87, 0x99, 0x90, 0x87, 0x2e,
        0x70, 0x43, 0x7c, 0x6a, 0x65, 0x7b, 0x57, 0x3e,
        0x98, 0x37, 0x97, 0x3a, 0xf2, 0xcd, 0x3e, 0x79,
        0xd5, 0x2d, 0xe6, 0xde, 0x68, 0xcc, 0x07, 0xfc,
        0x4f, 0xd4, 0xc1, 0x6f, 0x4a, 0xcf, 0xa6, 0xe8,
      ]
      key = [
        0xf6, 0xd2, 0x73, 0x8e, 0x25, 0x89, 0xcb, 0x88,
        0x48, 0x7a, 0xa5, 0xe4, 0x98, 0x34, 0xf4, 0x6e,
        0x79, 0x55, 0x0c, 0xb2, 0xfa, 0x39, 0x3c, 0x80,
        0xcc, 0xb6, 0x7f, 0x93, 0xf9, 0x3b, 0x5c, 0x3c,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0xe7, 0xf5, 0x66, 0x7b, 0xb6, 0x1f, 0x4f, 0x31,
        0xdc, 0x45, 0xd1, 0x47, 0x10, 0xaf, 0x70, 0x12,
        0xb7, 0xcb, 0x3d, 0x5b, 0xef, 0xdb, 0x45, 0xce,
        0xa7, 0x88, 0x08, 0x8c, 0x4a, 0x52, 0xa4, 0x1b,
        0x2d, 0xbe, 0xc0, 0xd0, 0xcb, 0xfc, 0xa2, 0x4b,
        0x14, 0x71, 0x57, 0x6f, 0x62, 0xe6, 0xfc, 0x14,
        0xb7, 0x45, 0xb2, 0x43, 0xf2, 0xbc, 0x90, 0xed,
        0x86, 0xb3, 0xdc, 0x03, 0xda, 0x4d, 0x82, 0x52,
        0xf6, 0x68, 0xa9, 0x05, 0x6e, 0x8d, 0x2c, 0xe1,
        0x84, 0x76, 0x6b, 0x44, 0x5e, 0x1e, 0xfc, 0xba,
        0x7f, 0x6c, 0x1f, 0x80, 0x5a, 0x33, 0x5d, 0x55,
        0xa9, 0xa4, 0x44, 0x71, 0x71, 0x0d, 0xa5, 0x64,
        0x11, 0xfa, 0xce, 0x44, 0xfb, 0xba, 0x5b, 0x70,
        0x24, 0xb1, 0xdb, 0x71, 0x21, 0x16, 0x85, 0x30,
        0xe0, 0xf3, 0x46, 0xac, 0x33, 0x36, 0xd5, 0xe0,
        0x39, 0x02, 0xb2, 0xbb, 0xe0, 0xa7, 0x30, 0x4e,
        0xa3, 0xe0, 0x14, 0x40, 0xb4, 0x4a, 0x6e, 0x4c,
        0x69, 0x93, 0x91, 0x6b, 0xc6, 0x77, 0x3f, 0x07,
      ]
    end

    it "should encrypt case 9 in CBC mode" do
      u = AES::Utils.new(256, AES::Mode::CBC)
      plaintext = [
        0x45, 0xb7, 0xcf, 0x11, 0x83, 0x95, 0x38, 0xda,
        0x7d, 0xa1, 0xca, 0x40, 0xc3, 0xf4, 0xb9, 0x24,
        0xa3, 0xf6, 0xac, 0xa5, 0x3d, 0x3d, 0x49, 0x6f,
        0x4f, 0x93, 0x5f, 0xf6, 0x8a, 0xd8, 0xe5, 0x4d,
        0x69, 0xe4, 0x85, 0x1f, 0xdc, 0x21, 0xcd, 0xfd,
        0x62, 0xa0, 0x53, 0xa2, 0xea, 0xaa, 0x82, 0x9d,
        0x14, 0xde, 0x2a, 0x05, 0x7f, 0xde, 0x14, 0x44,
        0xed, 0xac, 0x8f, 0xdf, 0xb5, 0x95, 0x29, 0x11,
        0x30, 0x73, 0x92, 0x7e, 0x19, 0x37, 0xe6, 0x54,
        0x36, 0x0b, 0x21, 0xf5, 0x9a, 0xb7, 0xdd, 0xde,
        0xad, 0xc2, 0x36, 0x05, 0x5e, 0x7b, 0x47, 0xcd,
        0x08, 0x9a, 0xfe, 0xf3, 0x6f, 0x7b, 0x73, 0x12,
        0x25, 0x67, 0xe2, 0x59, 0x27, 0x19, 0x7a, 0x4c,
        0x06, 0x8c, 0x7d, 0x87, 0x99, 0x90, 0x87, 0x2e,
        0x70, 0x43, 0x7c, 0x6a, 0x65, 0x7b, 0x57, 0x3e,
        0x98, 0x37, 0x97, 0x3a, 0xf2, 0xcd, 0x3e, 0x79,
        0xd5, 0x2d, 0xe6, 0xde, 0x68, 0xcc, 0x07, 0xfc,
        0x4f, 0xd4, 0xc1, 0x6f, 0x4a, 0xcf, 0xa6, 0xe8,
      ]
      key = [
        0xf6, 0xd2, 0x73, 0x8e, 0x25, 0x89, 0xcb, 0x88,
        0x48, 0x7a, 0xa5, 0xe4, 0x98, 0x34, 0xf4, 0x6e,
        0x79, 0x55, 0x0c, 0xb2, 0xfa, 0x39, 0x3c, 0x80,
        0xcc, 0xb6, 0x7f, 0x93, 0xf9, 0x3b, 0x5c, 0x3c,
      ]
      ciphertext = u.encrypt(plaintext, key)
      ciphertext.should eq [
        0xe7, 0xf5, 0x66, 0x7b, 0xb6, 0x1f, 0x4f, 0x31,
        0xdc, 0x45, 0xd1, 0x47, 0x10, 0xaf, 0x70, 0x12,
        0xfe, 0xbd, 0xb1, 0x04, 0x7f, 0xea, 0xcb, 0x3e,
        0x0b, 0xbc, 0xd6, 0x94, 0x62, 0x01, 0x53, 0x47,
        0xfa, 0x31, 0x76, 0xac, 0x7e, 0x8d, 0x8c, 0xf1,
        0xd9, 0x0e, 0x13, 0x61, 0x17, 0x49, 0x03, 0xd1,
        0xd4, 0xe6, 0xdf, 0xf8, 0xa1, 0x22, 0x37, 0xd7,
        0x62, 0xcf, 0xda, 0xc2, 0x65, 0x69, 0xe6, 0xfc,
        0x9b, 0x98, 0xd7, 0xdb, 0x66, 0x27, 0xd1, 0x16,
        0x27, 0x58, 0x3a, 0xc5, 0xaa, 0x03, 0x9c, 0x3a,
        0xac, 0x84, 0x8c, 0x5e, 0x84, 0x36, 0x82, 0x31,
        0x60, 0xbd, 0xa1, 0x14, 0x4f, 0xa1, 0x44, 0xfa,
        0x8d, 0x9f, 0x2f, 0xb4, 0x90, 0x1e, 0xea, 0xc1,
        0x2a, 0x71, 0x23, 0x3d, 0x1f, 0x6b, 0x80, 0x4e,
        0xd4, 0xf5, 0xc4, 0xf2, 0xcf, 0xd6, 0x10, 0xda,
        0x3b, 0x44, 0xdb, 0xe6, 0x65, 0x9b, 0xc8, 0x54,
        0x56, 0xf9, 0xd2, 0x5e, 0xa2, 0xb7, 0x05, 0xe0,
        0x6a, 0x6f, 0x43, 0x4f, 0x4d, 0x44, 0xfb, 0xe7,
      ]
    end
  end
end
