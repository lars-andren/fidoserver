package util;

public class ReturnPair<Boolean, V> {

    private Boolean returnSomeValue;

    private V valueToReturn;

    public ReturnPair() {}

    public ReturnPair(Boolean returnSomeValue, V valueToReturn) {

        this.returnSomeValue = returnSomeValue;
        this.valueToReturn = valueToReturn;
    }

    public Boolean returnSomeValue() {
        return returnSomeValue;
    }

    public void setReturnSomeValue(Boolean returnSomeValue) {
        this.returnSomeValue = returnSomeValue;
    }

    public V getValueToReturn() {
        return valueToReturn;
    }

    public void setValueToReturn(V valueToReturn) {
        this.valueToReturn = valueToReturn;
    }

    @Override
    public String toString() {
        return String.format("{ReturnPair returning <%s, %s>}", returnSomeValue, valueToReturn);
    }
}
