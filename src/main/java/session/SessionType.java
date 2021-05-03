package session;

public enum SessionType {

    REGISTER("register"),
    AUTHENTICATE("auhtenticate");

    public final String label;

    SessionType(String label) {
        this.label = label;
    }

    public String getLabel() {
        return this.label;
    }
}
