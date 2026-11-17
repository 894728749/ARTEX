/* Fixed, harmless inferior used only by native-runner doctor. */
int main(void) {
    volatile int value = 42;
    return value == 42 ? 0 : 1;
}
