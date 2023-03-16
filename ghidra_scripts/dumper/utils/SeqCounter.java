package dumper.utils;

public class SeqCounter {
    private int id = 0;

    public int next() {
        return id++;
    }
}
