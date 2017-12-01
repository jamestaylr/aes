module AES
  class Utils
    def initialize(size)
      case size
      when 128
        @num_rounds = 10
        @key_size = 4
      when 192
        @num_rounds = 12
        @key_size = 6
      when 256
        @num_rounds = 14
        @key_size = 8
      else
        raise ArgumentError.new("Unknown encryption size")
      end

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

    def key_expansion(key : Array(UInt8))
      w = Array(UInt8).new(4 * AES::NUM_COLUMNS * (@num_rounds + 1), 0.to_u8)
      w.fill(0, 4 * @key_size) { |j| key[j] }

      # Expand the key
      (@key_size...AES::NUM_COLUMNS * (@num_rounds + 1)).each do |i|
        ekc = (0...4).map { |j| w[((i - 1) * 4) + j] }
        ekp = (0...4).map { |j| w[((i - @key_size) * 4) + j] }

        if i % @key_size == 0
          ekc = sub_word(rot_word(ekc))
          ekc[0] ^= rcon((i / @key_size) - 1)
        elsif @key_size == 8 && i % 4 == 0
          ekc = sub_word(ekc)
        else
          ekc = ekc.map { |j| j.to_i32 }
        end

        temp = ekc.zip(ekp).map { |j, k| j ^ k }
        w.fill(i * 4, 4) { |j| temp[j % 4].to_u8 }
      end
      w
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
