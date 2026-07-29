package com.tester4real.personalauthenticator.vault

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LockStateMachineTest {
    @Test
    fun processStartScreenOffAndManualActions_lockImmediately() {
        val lock = LockStateMachine()
        assertTrue(lock.isLocked)
        lock.authenticated()
        assertFalse(lock.isLocked)
        lock.screenTurnedOff()
        assertTrue(lock.isLocked)
        lock.authenticated()
        lock.lockNow()
        assertTrue(lock.isLocked)
        lock.authenticated()
        lock.processStarted()
        assertTrue(lock.isLocked)
    }

    @Test
    fun backgroundLocksAtThirtySecondsButNotBefore() {
        val lock = LockStateMachine()
        lock.authenticated()
        lock.movedToBackground(10_000)
        lock.movedToForeground(39_999)
        assertFalse(lock.isLocked)

        lock.movedToBackground(40_000)
        lock.movedToForeground(70_000)
        assertTrue(lock.isLocked)
    }
}
