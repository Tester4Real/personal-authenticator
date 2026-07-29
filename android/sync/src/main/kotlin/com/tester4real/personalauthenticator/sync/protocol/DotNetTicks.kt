package com.tester4real.personalauthenticator.sync.protocol

import java.time.Instant

object DotNetTicks {
    private const val TICKS_AT_UNIX_EPOCH = 621_355_968_000_000_000L
    private const val TICKS_PER_SECOND = 10_000_000L

    fun fromInstant(value: Instant): Long =
        Math.addExact(
            TICKS_AT_UNIX_EPOCH,
            Math.addExact(
                Math.multiplyExact(value.epochSecond, TICKS_PER_SECOND),
                value.nano.toLong() / 100L,
            ),
        )

    fun toInstant(ticks: Long): Instant {
        require(ticks >= 0)
        val unixTicks = ticks - TICKS_AT_UNIX_EPOCH
        val seconds = Math.floorDiv(unixTicks, TICKS_PER_SECOND)
        val remainder = Math.floorMod(unixTicks, TICKS_PER_SECOND)
        return Instant.ofEpochSecond(seconds, remainder * 100)
    }
}
