module BitAccess
  def [](range)
    if range.is_a?(Number)
      range = range..range
    end

    mask = range.map { |n| 1 << n }.sum
    (self & mask) >> range.min
  end
end

struct UInt16
  # TODO prevent global scoping out of AES module
  include BitAccess
end

module AES
  struct FiniteField
    property value : UInt16

    def initialize(value : Int)
      @value = value.to_u16
    end

    def +(other)
      FiniteField.new(value ^ other.value)
    end

    def -(other)
      FiniteField.new(value ^ other.value)
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

    private def degree(n)
      n.to_s(2).chars.size - 1
    end

    def %(other)
      dv = degree(@value)
      dc = degree(other.value)

      p = @value
      (0..dv - dc).reverse_each do |i|
        # TODO guard against timing attacks
        if p.to_u16[i + dc] != 0
          p = (other.value << i) ^ p
        end
      end
      FiniteField.new(p)
    end
  end
end
