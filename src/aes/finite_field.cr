module AES
  struct FiniteField
    property value : UInt8

    def initialize(value : Int)
      @value = value.to_u8
    end

    def value
      @value.to_i32
    end

    def +(other)
      FiniteField.new(value ^ other.value)
    end

    def -(other)
      FiniteField.new(value ^ other.value)
    end

    def self.zero
      FiniteField.new(0)
    end

    def *(other)
      p = 0x0
      a = @value
      b = other.value

      (0...8).each do |i|
        hbit = a & 0x80
        if b & 0x1 == 0x1
          p ^= a
        end

        a <<= 1
        if hbit == 0x80
          a ^= 0x1b
        end
        b >>= 1
      end
      FiniteField.new(p)
    end

    def ==(other)
      @value == other.value
    end
  end
end
