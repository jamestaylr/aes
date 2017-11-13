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
