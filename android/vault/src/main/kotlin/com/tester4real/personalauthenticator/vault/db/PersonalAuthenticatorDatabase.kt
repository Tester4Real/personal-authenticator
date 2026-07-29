package com.tester4real.personalauthenticator.vault.db

import android.content.Context
import android.content.ContextWrapper
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import java.io.File

@Database(
    entities = [
        AccountEntity::class,
        SecretVersionEntity::class,
        AccountHistoryEntity::class,
        SyncOperationEntity::class,
        CausalParentEntity::class,
        AppliedIdentityEntity::class,
        FieldHeadEntity::class,
        AliasEntity::class,
        ConflictEntity::class,
        OutboxEntity::class,
        RemoteCiphertextStagingEntity::class,
        DeviceClockEntity::class,
        SyncHealthEntity::class,
        KnownGitObjectEntity::class,
    ],
    version = 1,
    exportSchema = true,
)
abstract class PersonalAuthenticatorDatabase : RoomDatabase() {
    abstract fun vaultDao(): VaultDao

    fun verifyIntegrity() {
        val database = openHelper.readableDatabase
        database.query("PRAGMA integrity_check").use { cursor ->
            check(cursor.moveToFirst() && cursor.getString(0) == "ok") {
                "SQLite integrity verification failed."
            }
        }
        database.query("PRAGMA cipher_integrity_check").use { cursor ->
            check(!cursor.moveToFirst()) {
                "SQLCipher integrity verification failed: ${cursor.getString(0)}"
            }
        }
    }

    companion object {
        fun open(
            context: Context,
            sqlCipherPassphrase: ByteArray,
        ): PersonalAuthenticatorDatabase {
            require(sqlCipherPassphrase.size == 32)
            System.loadLibrary("sqlcipher")
            val protectedContext = NoBackupDatabaseContext(context)
            val factory = SupportOpenHelperFactory(
                sqlCipherPassphrase.copyOf(),
                null,
                true,
            )
            return Room.databaseBuilder(
                protectedContext,
                PersonalAuthenticatorDatabase::class.java,
                DATABASE_NAME,
            )
                .openHelperFactory(factory)
                .build()
        }

        private const val DATABASE_NAME = "vault.db"
    }
}

private class NoBackupDatabaseContext(
    base: Context,
) : ContextWrapper(base) {
    override fun getDatabasePath(name: String): File {
        val directory = File(noBackupFilesDir, "vault")
        directory.mkdirs()
        return File(directory, name)
    }
}
