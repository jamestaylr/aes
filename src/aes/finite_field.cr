module AES
  struct FiniteField
    property value : UInt8

    # Create a new object
    #
    # Must have a value which fits in `UInt8` less than 255 or a byte
    def initialize(value : Int)
      @value = value.to_u8
    end

    # Return the `Int32` value of the object
    def value
      @value.to_i32
    end

    # Add with *other*
    def +(other)
      FiniteField.new(value ^ other.value)
    end

    # Subtract with *other*
    def -(other)
      FiniteField.new(value ^ other.value)
    end

    # Return the zero valued object
    def self.zero
      FiniteField.new(0)
    end

    # Multiply with *other*
    #
    # OPTIMIZE use log and antilog table during GF(2^8) computation
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

    # Check equality against *other*
    def ==(other)
      @value == other.value
    end
  end
end
