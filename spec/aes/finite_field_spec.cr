require "../../spec_helper"

describe AES::FiniteField do
  describe "#+" do
    it "should add" do
      a = AES::FiniteField.new(0b01010011)
      b = AES::FiniteField.new(0b11001010)
      (a + b).should eq AES::FiniteField.new(0b10011001)
    end
  end

  describe "#-" do
    it "should subtract" do
      a = AES::FiniteField.new(0b01010011)
      b = AES::FiniteField.new(0b11001010)
      (a + b).should eq AES::FiniteField.new(0b10011001)
    end
  end

  describe "#*" do
    it "should multiply" do
      a = AES::FiniteField.new(0b111)
      b = AES::FiniteField.new(0b101)
      (a * b).should eq AES::FiniteField.new(0b11011)
    end
  end
end
