module AES
  class Utils
    private def print_state(msg : String, state : Array(Int))
      fmt = state.map { |x| x.to_s(16).rjust(2, '0') }
      fmt.unshift("#{msg}:\t")
      puts(fmt.join(""))
    end

    def process(plaintext : Array(Int), key : Array(Int))
      blks = [] of Array(Int32)
      plaintext.each_slice(16) { |j| blks << j }

      init_vector = Array(Int32).new(16, 0)
      blks.map do |blk|
        # TODO create block generator
        blk.concat(blk.size != 16 ? Array(Int32).new(size = 16 - blk.size,
          value = 0) : [] of Int32)

        if @mode.cbc? && @process.encrypt?
          blk = blk.zip(init_vector).map { |j, k| j ^ k }
        end

        if @process.encrypt?
          processed = encrypt_block(blk.clone, key)
        else
          processed = decrypt_block(blk.clone, key)
        end

        if @mode.cbc? && @process.encrypt?
          init_vector = processed
        elsif @mode.cbc? && @process.decrypt?
          processed = processed.zip(init_vector).map { |j, k| j ^ k }
          init_vector = blk
        end
        processed
      end.flatten
    end

    def decrypt_block(plaintext : Array(Int), key : Array(Int))
      expanded = key_expansion(key)
      state = add_round_key(plaintext, expanded, @num_rounds)

      (1...@num_rounds).reverse_each do |i|
        # TODO OOP or functional method chaining
        state = sub_bytes(shift_rows(state))
        state = mix_columns(add_round_key(state, expanded, i))
      end
      state = sub_bytes(shift_rows(state))
      add_round_key(state, expanded, 0)
    end

    def encrypt_block(plaintext : Array(Int), key : Array(Int))
      expanded = key_expansion(key)
      state = add_round_key(plaintext, expanded, 0)

      (1...@num_rounds).each do |i|
        # TODO OOP or functional method chaining
        state = shift_rows(sub_bytes(state))
        state = add_round_key(mix_columns(state), expanded, i)
      end
      state = shift_rows(sub_bytes(state))
      add_round_key(state, expanded, @num_rounds)
    end
  end
end
