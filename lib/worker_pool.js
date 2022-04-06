const { AsyncResource } = require('async_hooks');
const { EventEmitter } = require('events');
const { Worker } = require('worker_threads');

const kTaskInfo = Symbol('kTaskInfo');
const kWorkerFreedEvent = Symbol('kWorkerFreedEvent');

class WorkerPoolTaskInfo extends AsyncResource {
    constructor(callback, onData, inParallel) {
        super('WorkerPoolTaskInfo');
        this.onData = onData;
        this.callback = callback;
        this.inParallel = inParallel;
    }

    done(err, result) {
        this.runInAsyncScope(this.callback, null, err, result);
        this.emitDestroy();  // `TaskInfo`s are used only once.
    }

    send(data) {
        if (this.onData) this.runInAsyncScope(this.onData, null, data);
    }
}

class WorkerPool extends EventEmitter {
    constructor(workerFile, numThreads) {
        super();

        this.workerFile = workerFile;
        this.workers = [];
        this.freeWorkers = [];
        this.tasks = [];
        this.numThreads = numThreads;

        for (let i = 0; i < numThreads; i++)
            this.addNewWorker();

        // Any time the kWorkerFreedEvent is emitted, dispatch
        // the next task pending in the queue, if any.
        this.on(kWorkerFreedEvent, () => {
            while (this.tasks.length > 0) {
                const { task, callback, onData, inParallel } = this.tasks.shift();
                const wasRunImmediately = this.runTask(task, callback, onData, inParallel);
                if (!wasRunImmediately) break;
                // Not checking free length here to force falsy wasRunImmediately
            }
        });
    }

    addNewWorker() {
        const worker = new Worker(this.workerFile);
        worker.on('message', msg => {
            if (msg !== 'done')
                return worker[kTaskInfo].send(msg);

            worker[kTaskInfo].done(null, msg);
            worker[kTaskInfo] = null;
            this.freeWorkers.push(worker);
            this.emit(kWorkerFreedEvent);
        });
        worker.on('error', (err) => {
            // In case of an uncaught exception: Call the callback that was passed to
            // `runTask` with the error.
            if (worker[kTaskInfo])
                worker[kTaskInfo].done(err, null);
            else
                this.emit('error', err);
            // Remove the worker from the list and start a new Worker to replace the
            // current one.
            this.workers.splice(this.workers.indexOf(worker), 1);
            this.addNewWorker();
        });
        this.workers.push(worker);
        this.freeWorkers.push(worker);
        this.emit(kWorkerFreedEvent);
    }

    canRunTaskImmediately(inParallel) {
        if (this.freeWorkers.length === 0) return false;
        if (inParallel) {
            const isRunningNonParallel = !this.workers.every(worker => worker[kTaskInfo]?.inParallel ?? true);
            if (isRunningNonParallel) return false;
        } else {
            if (this.freeWorkers.length < this.numThreads) return false;
        }

        return true;
    }

    runTask(task, callback, onData, inParallel = true) {
        if (!this.canRunTaskImmediately(inParallel)) {
            this.tasks.push({ task, callback, onData, inParallel });
            return;
        }

        const worker = this.freeWorkers.pop();
        worker[kTaskInfo] = new WorkerPoolTaskInfo(callback, onData, inParallel);
        worker.postMessage(task);

        return true;
    }

    close() {
        for (const worker of this.workers) worker.terminate();
    }
}

module.exports = WorkerPool;