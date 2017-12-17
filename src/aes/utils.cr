module AES
  class Utils
    # Creates an instance of AES utilizes with predefined options
    #
    # - *key* used to infer the number of rounds and key expansion size
    # - *mode* to set multiblock process behavior
    # - *process* defines whether helper functions should encrypt or decrypt
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

      # Precompute GF(2^8) tables for multiplication and modular inverse
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

    # Rotates a byte array appropriate to the process mode
    def rot_word(w : Array(Int), inv? = @process.decrypt?)
      if inv?
        w[0, 3].insert(0, w[3])
      else
        w[1, 3] << w[0]
      end
    end

    # Partitions the *blk* to call `Utils#sub_word`
    def sub_bytes(blk : Array(Int))
      # Breaks the array into arrays of four elements representing words
      cols = [] of Array(Int32)
      blk.each_slice(4) { |j| cols << j }

      cols.map { |w| sub_word(w) }.flatten
    end

    # Performs an SBOX substitution appropriate to the process mode
    def sub_word(w : Array(Int), inv? = @process.decrypt?)
      sbox_table = inv? ? AES::SBOX_INV : AES::SBOX
      w.map { |j| sbox_table[j] }
    end

    # Rotates each row of a matrix represented by *blk* based on the row offset
    #
    # The original matrix state
    # ```text
    # s(0,0) s(0,1) s(0,2) s(0,3)
    # s(1,0) s(1,1) s(1,2) s(1,3)
    # s(2,0) s(2,1) s(2,2) s(2,3)
    # s(3,0) s(3,1) s(3,2) s(3,3)
    # ```
    #
    # becomes
    # ```text
    # s(0,0) s(0,1) s(0,2) s(0,3)
    # s(1,1) s(1,2) s(1,3) s(1,0)
    # s(2,2) s(2,3) s(2,0) s(2,1)
    # s(3,3) s(3,0) s(3,1) s(3,2)
    # ```
    #
    def shift_rows(blk : Array(Int))
      # Breaks the array into a matrix with rows of four elements
      cols = [] of Array(Int32)
      blk.each_slice(4) { |j| cols << j }

      b = cols.transpose.map_with_index do |r, i|
        (0...i).each do
          r = rot_word(r)
        end
        r
      end.transpose.flatten
    end

    # XORs the *blk* with the appropriate section of the *key* based on *round*
    def add_round_key(blk : Array(Int), key : Array(Int), round : Int)
      (0...NUM_COLUMNS * 4).each do |c|
        # Loop through the entire block
        blk[c] ^= key[(round * NUM_COLUMNS * 4) + c]
      end
      blk
    end

    # Multiplies *blk* represented as an matrix with `#MIX_TABLE` or
    # `#MIX_TABLE_INV`
    #
    # Performs the matrix multiplication by iterating over each column
    # in the *blk* matrix and each row in the predetermined table
    # ```text
    # 0x02 0x03 0x01 0x01
    # 0x01 0x02 0x03 0x01
    # 0x01 0x01 0x02 0x03
    # 0x03 0x01 0x01 0x02
    # ```
    #
    def mix_columns(blk : Array(Int))
      # Breaks the array into a matrix with rows of four elements
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

    # Returns the round constant for the given round
    #
    # The constant will always be of the form:
    # ```text
    # rcon[i] = (rc[i], 0x00, 0x00, 0x00)
    # ```
    # Modulus occurs with `#AES_POLYNOMIAL` through `FiniteField`
    # multiplication
    #
    # OPTIMIZE precompute rcon values
    def rcon(round : Int)
      a = FiniteField.new(0x1)
      (0...round).each do |r|
        # Shift via multiplication taking the modulus
        a = a * FiniteField.new(2)
      end
      a.value
    end

    # Expands the initial key based on the number of rounds
    #
    # - A 16 byte key will be expanded to 176 bytes
    # - A 24 byte key will be expanded to 208 bytes
    # - A 32 byte key will be expanded to 240 bytes
    #
    # The expanded key is prefixed with the initial key and at every `@key_size`
    # word, `Utils#sub_word`, `Utils#rot_word` will be called on the previous
    # word and XOR'd with the start of the previous block and the `Utils#rcon`
    #
    # During 32 byte key expansion in 256 bit AES there is an additional call
    # to `Utils#sub_word` between `@key_size` word intervals
    def key_expansion(key : Array(Int))
      inv? = false
      # Allocate space for the expanded key
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
        # Fill the expanded key space allocation
        w.fill(i * 4, 4) { |j| temp[j % 4] }
      end
      w
    end

    # Computes the modular inverse
    #
    # *value* which must be a `FiniteField` and the computation uses the
    # precomputed `@log_table` and `@antilog_table`
    def modular_inverse(value : FiniteField)
      if value == 0
        return value
      end

      x = 255 - @log_table[value.clamp(0..255)]
      FiniteField.new(@antilog_table[x])
    end
  end
end
