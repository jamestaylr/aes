module AES
  class Utils
    def encrypt(plaintext : Array(Int), key : Array(Int))
      blks = [] of Array(Int32)
      plaintext.each_slice(16) { |j| blks << j }
      blks.map{|blk| encrypt_block(blk, key)}.flatten
    end

    def encrypt_block(plaintext : Array(Int), key : Array(Int))
      expanded = key_expansion(key)
      state = add_round_key(plaintext, expanded, 0)

      (1...@num_rounds).each do |i|
        # TODO OOP or functional method chaining
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, expanded, i)
      end
      state = sub_bytes(state)
      state = shift_rows(state)
      state = add_round_key(state, expanded, @num_rounds)
      state
    end
  end
end
