module AES
  class Utils
    def initialize(key : Array(Int32), mode = AES::Mode::ECB, process = AES::Process::Encrypt)
      case key.size
      when 16
        # 128 bit
        @num_rounds = 10
        @key_size = 4
      when 24
        # 192 bit
        @num_rounds = 12
        @key_size = 6
      when 32
        # 256 bit
        @num_rounds = 14
        @key_size = 8
      else
        raise ArgumentError.new("Unknown key size #{key.size}")
      end
      @key = key
      @mode = mode
      @process = process

      @log_table = Array(Int32).new(size = 256, value = 0)
      @antilog_table = Array(Int32).new(size = 256, value = 0)

      g = FiniteField.new(3)
      t = FiniteField.new(1)
      (0...255).each do |i|
        @log_table[t.value] = i
        @antilog_table[i] = t.value
        t *= g
      end
    end

    def rot_word(w : Array(Int), inv? = @process.decrypt?)
      if inv?
        w[0, 3].insert(0, w[3])
      else
        w[1, 3] << w[0]
      end
    end

    def sub_bytes(blk : Array(Int))
      cols = [] of Array(Int32)
      blk.each_slice(4) { |j| cols << j }

      cols.map { |w| sub_word(w) }.flatten
    end

    def sub_word(w : Array(Int), inv? = @process.decrypt?)
      sbox_table = inv? ? AES::SBOX_INV : AES::SBOX
      w.map { |j| sbox_table[j] }
    end

    def shift_rows(blk : Array(Int))
      cols = [] of Array(Int32)
      blk.each_slice(4) { |j| cols << j }

      b = cols.transpose.map_with_index do |r, i|
        (0...i).each do
          r = rot_word(r)
        end
        r
      end.transpose.flatten
    end

    def add_round_key(blk : Array(Int), key : Array(Int), round : Int)
      (0...NUM_COLUMNS * 4).each do |c|
        blk[c] ^= key[(round * NUM_COLUMNS * 4) + c]
      end
      blk
    end

    def mix_columns(blk : Array(Int))
      cols = [] of Array(FiniteField)
      blk.each_slice(4) { |j| cols << j.map { |k| FiniteField.new(k) } }
      table = @process.encrypt? ? MIX_TABLE : MIX_TABLE_INV
      return cols.map do |col|
        table.map do |row|
          a = row.map { |x| FiniteField.new(x) }.zip(col).sum do |r, c|
            r * c
          end
          a.value
        end
      end.flatten
    end

    def rcon(round : Int)
      a = FiniteField.new(0x1)
      (0...round).each do |r|
        a = a * FiniteField.new(2)
      end
      a.value
    end

    def key_expansion(key : Array(Int))
      inv? = false
      w = Array(Int32).new(4 * AES::NUM_COLUMNS * (@num_rounds + 1), 0)
      w.fill(0, 4 * @key_size) { |j| key[j] }

      # Expand the key
      (@key_size...AES::NUM_COLUMNS * (@num_rounds + 1)).each do |i|
        ekc = (0...4).map { |j| w[((i - 1) * 4) + j] }
        ekp = (0...4).map { |j| w[((i - @key_size) * 4) + j] }

        if i % @key_size == 0
          ekc = sub_word(rot_word(ekc, inv?), inv?)
          ekc[0] ^= rcon((i / @key_size) - 1)
        elsif @key_size == 8 && i % 4 == 0
          ekc = sub_word(ekc, inv?)
        else
          ekc = ekc.map { |j| j.to_i32 }
        end

        temp = ekc.zip(ekp).map { |j, k| j ^ k }
        w.fill(i * 4, 4) { |j| temp[j % 4] }
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
