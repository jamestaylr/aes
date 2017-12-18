require "../src/*"

module EncryptionSample
  include AES

  def self.convert(unfmt : String)
    fmt = [] of Int32
    unfmt.split("").each_slice(2) { |x| fmt << x.join("").to_i(16) }
    fmt
  end

  def self.main
    plaintext = %q{
        e94ed7741f99d306e406f70386fdd7cc9fb2d5928fed4aad3f4f42fa4e91b4a1
        e47949125a755c2f92d11ab05cf5092b6f267beddd27763e304e8926ac80fb17
        634f1dcb6bd3bc3f5a422ca3a9dc355532ce4bfadc6cff73092a3635a4f574c3
        d7c28dedbbb7fc9ecb3c912740b1dfb7c0038ab9b1d5e48297f5ca83ed23840f
        f15f807691f827e75762d41b3279f229778b1258989a6b6e430e69960fa8ff85
        7b427f1bcb690f6780d45ecc4cda297b
    }.delete(" \t\r\n")
    key = "c06df9c06a06a82ee8145a2039b767fb"

    puts(plaintext)

    u = AES::Utils.new(convert(key), AES::Mode::ECB, AES::Process::Encrypt)
    ciphertext = u.process(convert(plaintext))

    puts(ciphertext.map { |x| x.to_s(16).rjust(2, '0') }.join(""))
  end

  main
end
