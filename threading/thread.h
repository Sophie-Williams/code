#pragma once
#ifdef QT_CORE_LIB //Qt makes a "moc" file which requires you to include your dependencies in the header file.
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <Windows.h>
#include <list>
#include <memory>
#include <mutex>
#include <future>
#include <chrono>
#include <qobject.h>
#endif

//note: this is not a thread pool, threads cannot be re-used.
//I could use a thread pool, but I decided to go with this approach due to 

class ThreadList;
class Thread
#ifdef QT_CORE_LIB
	:public QObject
#endif
			{
#ifdef QT_CORE_LIB
	Q_OBJECT
#endif
public:
	Thread(ThreadList& tc);
	Thread(Thread&&) = delete;
	Thread(const Thread&) = delete;
	virtual ~Thread(); //https://stackoverflow.com/a/461224 -> "Virtual destructors are useful when you want to delete an instance of a derived class through a pointer to the base class."
	void start();
	bool wait(DWORD dwWaitTime = INFINITE);
	void wait_gui();
	void quit(); //requests the thread to stop.
	virtual BYTE type() { return 0; };
private:
	friend class ThreadList;
	HANDLE hThread;
	bool bStop;
	ThreadList& tc;
	virtual void ThreadEntry() = 0;
	virtual void done() {};
	void unregister();
	static DWORD WINAPI _ThreadEntry(Thread* t)
	{
		t->ThreadEntry();
		t->done();
		t->unregister();
		return NULL;
	};
protected:
	bool stop() { return bStop; };
	ThreadList& container() { return tc; };
};

class SocketThread :public Thread {
#ifdef QT_CORE_LIB
	Q_OBJECT
#endif
public:
	SocketThread(SOCKET sSocket, ThreadList& tc) :Thread(tc) {
		this->sSocket = sSocket;
	};
protected:
	SOCKET sSocket;
};

class ThreadList {
public:
	ThreadList();
	ThreadList(ThreadList&&) = delete;
	ThreadList(const ThreadList&) = delete;
	~ThreadList();
	void operator=(ThreadList&&) = delete;
	void operator=(const ThreadList&) = delete;

	//note: to use the iterators you must obtain a lock otherwise if a thread is removed it may invalidate the iterator.
	std::unique_lock<std::mutex> obtain_lock();
	std::list<std::shared_ptr<Thread>>::iterator begin();
	std::list<std::shared_ptr<Thread>>::iterator end();
	std::list<std::shared_ptr<Thread>>::const_iterator cbegin() const;
	std::list<std::shared_ptr<Thread>>::const_iterator cend() const;
	std::shared_ptr<Thread> at(size_t index);
	std::shared_ptr<Thread> operator[](size_t index) { return this->at(index); };
	size_t size() { std::lock_guard<std::mutex> lock(m_threads); return threads.size(); };
	void quit(); //WARNING: once you call quit(), you can no longer register threads to that instance unless you explicity call enable_thread_registration().
	void enable_thread_registration() { bRegistrationDisabled = false; };
private:
	bool bRegistrationDisabled;
	std::chrono::system_clock::time_point tasks_last_check;
	std::mutex m_tasks, m_threads; //std::recursive_mutex
	std::list<std::shared_ptr<Thread>> threads;
	std::list<std::future<void>> tasks;
	friend class Thread;
	void register_thread(Thread* thread);
	void unregister_thread(Thread* thread);
};

typedef ThreadList ThreadContainer;