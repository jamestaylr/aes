module AES
  class Utils
    private def print_state(msg : String, state : Array(Int))
      fmt = state.map { |x| x.to_s(16).rjust(2, '0') }
      fmt.unshift("#{msg}:\t")
      puts(fmt.join(""))
    end

    def encrypt(plaintext : Array(Int), key : Array(Int))
      blks = [] of Array(Int32)
      plaintext.each_slice(16) { |j| blks << j }

      init_vector = Array(Int32).new(16, 0)
      blks.map do |blk|
        blk.concat(blk.size != 16 ? Array(Int32).new(size = 16 - blk.size,
          value = 0) : [] of Int32)
        tmp = blk.zip(init_vector).map { |j, k| j ^ k }
        encrypted = encrypt_block(tmp, key)
        if @mode.cbc?
          init_vector = encrypted
        end
        encrypted
      end.flatten
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
