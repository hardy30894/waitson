public class Deadlock {
    static final Object A = new Object();
    static final Object B = new Object();

    public static void main(String[] args) throws Exception {
        System.out.println("READY " + ProcessHandle.current().pid());
        Thread left = new Thread(() -> {
            synchronized (A) {
                pause();
                synchronized (B) {
                }
            }
        }, "left");
        Thread right = new Thread(() -> {
            synchronized (B) {
                pause();
                synchronized (A) {
                }
            }
        }, "right");
        left.start();
        right.start();
        left.join();
    }

    static void pause() {
        try {
            Thread.sleep(300);
        } catch (InterruptedException e) {
        }
    }
}
