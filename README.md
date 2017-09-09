# code
Various projects.

ThreadList -> used to store subclassed Thread objects which will self-manage themselves(when a thread finishes, it will call ThreadList::unregister_thread() which will delete itself from the thread list).