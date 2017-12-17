module AES
  class Utils
    private def print_state(msg : String, state : Array(Int))
      fmt = state.map { |x| x.to_s(16).rjust(2, '0') }
      fmt.unshift("#{msg}:\t")
      puts(fmt.join(""))
    end

    # Performs the encryption or decryption process on *input*
    #
    # - *input* be of indeterminate size and will be padded with zeros
    # - Correctly performs with XOR with the initialization vector
    # - Contains logic for handling both `Mode#ECB` and `Mode#CBC` modes
    #
    # TODO create block generator
    def process(input : Array(Int))
      # Breaks the array into blocks of 16 elements representing bytes
      blks = [] of Array(Int32)
      input.each_slice(16) { |j| blks << j }

      # Setup initial parameters
      init_vector = Array(Int32).new(16, 0)
      expanded_key = key_expansion(@key)
      blks.map do |blk|
        # Pad the block if required
        blk.concat(blk.size != 16 ? Array(Int32).new(size = 16 - blk.size,
          value = 0) : [] of Int32)

        if @process.encrypt?
          # Perform encryption process
          if @mode.cbc?
            blk = blk.zip(init_vector).map { |j, k| j ^ k }
          end
          processed = encrypt_block(blk.clone, expanded_key)
          if @mode.cbc?
            init_vector = processed
          end
        else
          # Perform decryption process
          processed = decrypt_block(blk.clone, expanded_key)
          if @mode.cbc?
            processed = processed.zip(init_vector).map { |j, k| j ^ k }
            init_vector = blk
          end
        end

        processed
      end.flatten
    end

    # Decrypts a ciphertext block
    #
    # Calls the appropriate AES helper functions in inverse order
    #
    # TODO OOP or functional method chaining
    def decrypt_block(ciphertext : Array(Int), expanded_key : Array(Int))
      state = add_round_key(ciphertext, expanded_key, @num_rounds)

      (1...@num_rounds).reverse_each do |i|
        state = sub_bytes(shift_rows(state))
        state = mix_columns(add_round_key(state, expanded_key, i))
      end
      state = sub_bytes(shift_rows(state))
      add_round_key(state, expanded_key, 0)
    end

    # Encrypts a plaintext block
    #
    # Calls the appropriate AES helper functions
    #
    # TODO OOP or functional method chaining
    def encrypt_block(plaintext : Array(Int), expanded_key : Array(Int))
      state = add_round_key(plaintext, expanded_key, 0)

      (1...@num_rounds).each do |i|
        state = shift_rows(sub_bytes(state))
        state = add_round_key(mix_columns(state), expanded_key, i)
      end
      state = shift_rows(sub_bytes(state))
      add_round_key(state, expanded_key, @num_rounds)
    end
  end
end
