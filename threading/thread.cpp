#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <Windows.h>
#include <list>
#include <memory>
#include <mutex>
#include <future>
#include <chrono>
#include "thread.h"

using namespace std::chrono_literals;

Thread::Thread(ThreadList & tl):container(tl)
{
	hThread = INVALID_HANDLE_VALUE;
	bStop = false;
	container.register_thread(this); //WARNING: it will throw an exception if we're unable to register the thread. note: since we're throwing an exception from the constructor the instance will be freed.
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
		if (wait(0) == WAIT_OBJECT_0)
			return;
		::CloseHandle(hThread);
	}
	hThread = ::CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)&Thread::_entry, (LPVOID)this, NULL, nullptr);
}

bool Thread::wait(DWORD timeout)
{
	if (hThread == INVALID_HANDLE_VALUE)
		return true;
	return ::WaitForSingleObject(hThread, timeout) == WAIT_OBJECT_0;
}

void Thread::cleanup()
{
	container.unregister_thread(this);
}

ThreadList::ThreadList()
{
	bQuitting = false;
}

ThreadList::~ThreadList()
{
	this->quit();
	std::lock_guard<std::mutex> lock(m_tasks);
	//ensure all tasks are completed
	for (auto& task : tasks)
		task.wait(); //task.get();
}

void ThreadList::quit()
{
	std::lock_guard<std::mutex> lock(m_threads);
	bQuitting = true;
	for (auto& thread : threads) {
		thread->stop();
		thread->wait();
	}
}

void ThreadList::register_thread(Thread * thread)
{
	std::lock_guard<std::mutex> lock(m_threads);
	if (bQuitting)
		throw std::exception("Thread Registration disabled by ThreadList");
	threads.push_back(std::shared_ptr<Thread>(thread));
}

void ThreadList::unregister_thread(Thread * thread)
{
	std::lock_guard<std::mutex> lock(m_tasks);
	//remove completed tasks.
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