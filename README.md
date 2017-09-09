# code
Various projects.

ThreadList -> used to store subclassed Thread objects which will self-manage themselves(when a thread finishes, it will call ThreadList::unregister_thread() which will delete itself from the thread list).
usage:

class thrd :public Thread {
public:
	using Thread::Thread;
	~thrd() {
		OutputDebugStringA("~thrd()\r\n");
	};
private:
	void entry() override
	{
		OutputDebugStringA("hello from thread\r\n");
		if (is_stop_flag_set())
			OutputDebugStringA("stop flag set\r\n");
	};
};

//...

ThreadList tc;
		try {
			(new thrd(tc))->start();
		}
		catch (std::exception& e) {
			cout << "exception: " << e.what() << endl;
		}