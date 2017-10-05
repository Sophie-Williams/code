#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <Windows.h>
#include <list>
#include <memory>
#include <mutex>
#include <future>
#include <chrono>
#include "thread.h"

#ifdef QT_CORE_LIB
#include <qapplication.h>
#endif

using namespace std::chrono;


Thread::Thread(ThreadList& tc):tc(tc)
{
	hThread = INVALID_HANDLE_VALUE;
	bStop = false;
	tc.register_thread(this);
}

Thread::~Thread()
{
	if (hThread != INVALID_HANDLE_VALUE) {
		this->wait();
		::CloseHandle(hThread);
	}
}

void Thread::start()
{
	if (hThread != INVALID_HANDLE_VALUE) {
		if (!wait(0)) //we've previously created a thread and it's still running.
			return;
	}
	hThread = ::CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)&Thread::_ThreadEntry, this, NULL, nullptr);
}

bool Thread::wait(DWORD dwWaitTime)
{
	if (hThread != INVALID_HANDLE_VALUE)
		return ::WaitForSingleObject(hThread, dwWaitTime) == WAIT_OBJECT_0;
	return true;
}

void Thread::wait_gui()
{
	while (true) {
		if (wait(10))
			break;
#ifdef QT_CORE_LIB
		QCoreApplication::processEvents();
#else

#endif
	}
}

void Thread::quit()
{
	bStop = true;
}

void Thread::unregister()
{
	tc.unregister_thread(this);
}


ThreadList::ThreadList()
{
	tasks_last_check = std::chrono::system_clock::now();
	bRegistrationDisabled = false;
}

ThreadList::~ThreadList()
{
	this->quit();
	//ensure all tasks are completed.
	std::lock_guard<std::mutex> lock(m_tasks);
	for (auto& task : tasks)
		task.wait(); //task.get();
}

std::unique_lock<std::mutex> ThreadList::obtain_lock()
{
	return std::unique_lock<std::mutex>(m_threads);
}

std::list<std::shared_ptr<Thread>>::iterator ThreadList::begin()
{
	return threads.begin();
}

std::list<std::shared_ptr<Thread>>::iterator ThreadList::end()
{
	return threads.end();
}

std::list<std::shared_ptr<Thread>>::const_iterator ThreadList::cbegin() const
{
	return threads.cbegin();
}

std::list<std::shared_ptr<Thread>>::const_iterator ThreadList::cend() const
{
	return threads.cend();
}

std::shared_ptr<Thread> ThreadList::at(size_t index)
{
	std::lock_guard<std::mutex> lock(m_threads);
	if (index + 1 > threads.size())
		return std::shared_ptr<Thread>();
	auto it = std::next(threads.begin(), index);
	if (it != threads.end())
		return *it;
	return std::shared_ptr<Thread>();
}

void ThreadList::quit()
{
	std::lock_guard<std::mutex> lock(m_threads);
	bRegistrationDisabled = true;
	for (auto& thread : threads)
		thread->quit();
	for (auto& thread : threads)
#ifdef QT_CORE_LIB
		thread->wait_gui();
#else
		thread->wait();
#endif
	threads.clear();
}


void ThreadList::register_thread(Thread * thread)
{
	std::lock_guard<std::mutex> lock(m_threads);//std::lock_guard<std::recursive_mutex> lock(m_threads);
	if (bRegistrationDisabled)
		throw std::exception("Thread registration is disabled!");
	threads.push_back(std::shared_ptr<Thread>(thread));
}

void ThreadList::unregister_thread(Thread * thread)
{
	std::lock_guard<std::mutex> lock(m_tasks);
	//we remove tasks that have been completed to ensure we don't use up too much memory.
	if (std::chrono::system_clock::now() - tasks_last_check >= 10s) {
		for (auto it = tasks.begin(); it != tasks.end(); ) {
			if (it->wait_until(std::chrono::system_clock::now() + std::chrono::milliseconds(1)) == std::future_status::ready)
				it = tasks.erase(it);
			else
				it++;
		}
		tasks_last_check = std::chrono::system_clock::now();
	}
	//if you don't want to use std::async, with Windows you could use function QueueUserAPC instead with a function that does something similar to below:
	tasks.emplace_back(std::async(std::launch::async, [&, thread]() {
		std::lock_guard<std::mutex> lock(m_threads);
		this->threads.remove_if([thread](const std::shared_ptr<Thread>& wrapped_thread) -> bool { return wrapped_thread.get() == thread; });
	}));
}