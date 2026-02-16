import * as assert from 'assert';
import { RingBuffer } from '../securityPanel';

suite('RingBuffer Test Suite', () => {

    test('Add items within limit', () => {
        const rb = new RingBuffer<number>(3);
        rb.add(1);
        rb.add(2);
        assert.deepStrictEqual(rb.getAll(), [1, 2]);
    });

    test('Rotate items when full', () => {
        const rb = new RingBuffer<number>(3);
        rb.add(1);
        rb.add(2);
        rb.add(3);
        rb.add(4);
        assert.deepStrictEqual(rb.getAll(), [2, 3, 4]);
    });

    test('Get Latest', () => {
        const rb = new RingBuffer<string>(3);
        rb.add("a");
        rb.add("b");
        assert.strictEqual(rb.getLatest(), "b");
    });

    test('Find Reverse', () => {
        const o1 = { id: 1, val: 'old' };
        const o2 = { id: 2, val: 'middle' };
        const o3 = { id: 1, val: 'new' };

        const rbObj = new RingBuffer<any>(5);
        rbObj.add(o1);
        rbObj.add(o2);
        rbObj.add(o3);

        const foundObj = rbObj.findReverse((x: any) => x.id === 1);
        assert.strictEqual(foundObj, o3); // Should be the newest one (last added)
    });

    test('Clear buffer', () => {
        const rb = new RingBuffer<number>(3);
        rb.add(1);
        rb.clear();
        assert.strictEqual(rb.getAll().length, 0);
    });
});
