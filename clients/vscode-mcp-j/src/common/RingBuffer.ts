
// Extracted for Unit Testing (Phase 50.2)
export class RingBuffer<T> {
    private buffer: T[] = [];

    constructor(public readonly maxSize: number) { }

    add(item: T) {
        this.buffer.push(item);
        if (this.buffer.length > this.maxSize) {
            this.buffer.shift();
        }
    }

    getAll(): T[] {
        return [...this.buffer];
    }

    getLatest(): T | undefined {
        return this.buffer[this.buffer.length - 1];
    }

    findReverse(predicate: (item: T) => boolean): T | undefined {
        // Search from newest to oldest
        for (let i = this.buffer.length - 1; i >= 0; i--) {
            if (predicate(this.buffer[i])) {
                return this.buffer[i];
            }
        }
        return undefined;
    }

    clear() {
        this.buffer = [];
    }
}
