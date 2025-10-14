#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// 通用信号处理函数
void signal_handler(int sig) {
    char msg[64];
    snprintf(msg, sizeof(msg), "Caught signal: %d (%s)\n", sig, strsignal(sig));
    write(STDOUT_FILENO, msg, strlen(msg)); // 使用异步安全的write
}

int main() {
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    // 遍历所有可捕获信号（1~31，除去SIGKILL和SIGSTOP）
    for (int sig = 1; sig <= 31; sig++) {
        if (sig == SIGKILL || sig == SIGSTOP) continue; // 无法拦截
        if (sigaction(sig, &sa, NULL) == -1) {
            perror("sigaction");
        }
    }

    printf("PID: %d (Try sending signals)\n", getpid());
    while (1) pause(); // 等待信号
}
