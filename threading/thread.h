#pragma once

class ThreadList;
class Thread {
public:
	Thread(ThreadList& tl);
	virtual ~Thread();
	void start();
	void stop() { bStop = true; };
	bool wait(DWORD timeout = INFINITE);
private:
	ThreadList& container;
	HANDLE hThread;
	bool bStop;
	virtual void entry() = 0;
	virtual void done() {};
	void cleanup();
	static DWORD WINAPI _entry(Thread* t)
	{
		t->entry();
		t->done();
		t->cleanup();
		return NULL;
	};
protected:
	bool is_stop_flag_set() const { return bStop; };
};

class SocketThread :public Thread {
public:
	SocketThread(SOCKET sSocket, ThreadList& tc) :Thread(tc) { this->sSocket = sSocket; };
private:
	SOCKET sSocket;
};

class ThreadList {
public:
	ThreadList();
	ThreadList(ThreadList&&) = delete;
	ThreadList(const ThreadList&) = delete;
	~ThreadList();
	void quit();
private:
	bool bQuitting;
	friend class Thread;
	std::chrono::system_clock::time_point tasks_last_check;
	std::list<std::shared_ptr<Thread>> threads;
	std::list<std::future<void>> tasks;
	std::mutex m_tasks, m_threads; //std::recursive_mutex
	void register_thread(Thread* thread);
	void unregister_thread(Thread* thread);
};

typedef ThreadList ThreadContainer;