module AES
  class Utils
    def initialize
      @log_table = Array(UInt8).new(size = 256, value = 0.to_u8)
      @antilog_table = Array(UInt8).new(size = 256, value = 0.to_u8)

      g = FiniteField.new(3)
      t = FiniteField.new(1)
      (0...255).map { |x| x.to_u8 }.each do |i|
        @log_table[t.value] = i
        @antilog_table[i] = t.value
        t *= g
      end
    end

    def rot_word(w : Array(UInt8))
      w[1, 3] << w[0]
    end

    def sub_word(w : Array(UInt8))
      w.map { |j| AES::SBOX[j] }
    end

    def rcon(round : Int)
      a = FiniteField.new(0x1)
      (0...round).each do |r|
        a = a * FiniteField.new(2)
      end
      a.value
    end

    def modular_inverse(a)
      if a == 0
        return a
      end

      x = 255 - @log_table[a.clamp(0..255)]
      FiniteField.new(@antilog_table[x])
    end
  end
end
