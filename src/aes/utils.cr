module AES
  class Utils
    def initialize
      @log_table = Array(UInt16).new(size = 256, value = 0.to_u16)
      @antilog_table = Array(UInt16).new(size = 256, value = 0.to_u16)

      g = FiniteField.new(3)
      t = FiniteField.new(1)
      (0...255).map { |x| x.to_u16 }.each do |i|
        @log_table[t.value] = i
        @antilog_table[i] = t.value
        t *= g
      end
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
