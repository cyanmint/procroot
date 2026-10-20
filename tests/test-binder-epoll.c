#include <fcntl.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <unistd.h>

int main(void)
{
	struct epoll_event event = { .events = EPOLLIN };
	int epoll_fd;
	int binder_fd;

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0) {
		perror("epoll_create1");
		return 1;
	}
	binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	if (binder_fd < 0) {
		perror("open /dev/binder");
		close(epoll_fd);
		return 2;
	}
	event.data.fd = binder_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &event) < 0) {
		perror("epoll_ctl ADD /dev/binder");
		close(binder_fd);
		close(epoll_fd);
		return 3;
	}
	puts("BINDER_EPOLL_ADD=PASS");
	close(binder_fd);
	close(epoll_fd);
	return 0;
}
