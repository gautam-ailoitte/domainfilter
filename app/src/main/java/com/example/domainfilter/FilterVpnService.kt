package com.example.domainfilter

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.preference.PreferenceManager
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class FilterVpnService : VpnService() {
    companion object {
        private const val TAG = "DomainFilter"

        // Actions
        const val ACTION_CONNECT = "com.example.domainfilter.CONNECT"
        const val ACTION_DISCONNECT = "com.example.domainfilter.DISCONNECT"

        // Notification
        private const val NOTIFICATION_CHANNEL_ID = "vpn_channel"
        private const val NOTIFICATION_ID = 1

        // Service state
        private val sRunning = AtomicBoolean(false)
        private val sFilteredCount = AtomicInteger(0)

        // Check if VPN is running
        @JvmStatic
        fun isRunning(): Boolean = sRunning.get()

        // Get count of filtered domains
        @JvmStatic
        fun getFilteredCount(): Int = sFilteredCount.get()

        // Load native library
        init {
            System.loadLibrary("domainfilter")
        }
    }

    // VPN parameters
    private var mInterface: ParcelFileDescriptor? = null
    private var mThread: Thread? = null
    private lateinit var mHandler: Handler
    private lateinit var mPrefs: SharedPreferences

    // JNI methods
    private external fun jniInit()
    private external fun jniStart(fd: Int)
    private external fun jniStop()
    private external fun jniGetFilteredCount(): Int

    override fun onCreate() {
        super.onCreate()
        mPrefs = PreferenceManager.getDefaultSharedPreferences(this)
        mHandler = Handler(Looper.getMainLooper())

        // Initialize native code
        jniInit()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent != null) {
            val action = intent.action

            when (action) {
                ACTION_CONNECT -> {
                    startVpn()
                    return START_STICKY
                }
                ACTION_DISCONNECT -> {
                    stopVpn()
                    stopSelf()
                    return START_NOT_STICKY
                }
            }
        }

        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun startVpn() {
        // If already running, return
        if (sRunning.get()) {
            return
        }

        // Create notification channel for Android 8+
        createNotificationChannel()

        // Build the VPN interface
        val builder = Builder().apply {
            // Add addresses
            addAddress("10.0.0.2", 32)
            addRoute("0.0.0.0", 0)

            // Add DNS servers
            addDnsServer("8.8.8.8")
            addDnsServer("8.8.4.4")

            // Set session name
            setSession(getString(R.string.app_name))

            // MTU
            setMtu(1500)

            // Exclude our app from the VPN
            try {
                addDisallowedApplication(packageName)
            } catch (e: PackageManager.NameNotFoundException) {
                Log.e(TAG, "Failed to exclude app from VPN", e)
            }
        }

        // Establish the VPN interface
        try {
            mInterface = builder.establish()
            if (mInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                return
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error establishing VPN", e)
            return
        }

        // Start a foreground notification with the correct service type
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                buildNotification(),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(NOTIFICATION_ID, buildNotification())
        }

        // Set running flag
        sRunning.set(true)
        sFilteredCount.set(0)

        // Start the VPN thread
        val fd = mInterface!!.fd
        mThread = Thread({
            Log.i(TAG, "Starting VPN thread with fd: $fd")
            jniStart(fd)
        }, "VpnThread").apply { start() }

        // Schedule statistics updates
        mHandler.postDelayed(this::updateStatistics, 1000)

        Log.i(TAG, "VPN service started")
    }

    private fun stopVpn() {
        // If not running, return
        if (!sRunning.get()) {
            return
        }

        // Signal the native thread to stop
        jniStop()

        // Interrupt the thread
        mThread?.let {
            try {
                it.interrupt()
                it.join(1000)
            } catch (e: InterruptedException) {
                Log.e(TAG, "Error joining thread", e)
            }
            mThread = null
        }

        // Close the interface
        try {
            mInterface?.close()
            mInterface = null
        } catch (e: IOException) {
            Log.e(TAG, "Error closing VPN interface", e)
        }

        // Update state
        sRunning.set(false)

        // Stop foreground
        stopForeground(true)

        Log.i(TAG, "VPN service stopped")
    }

    // Called from native code
    @Suppress("unused")
    fun protectSocket(socket: Int) {
        if (!protect(socket)) {
            Log.e(TAG, "Failed to protect socket: $socket")
        }
    }

    // Update statistics
    private fun updateStatistics() {
        if (sRunning.get()) {
            // Update blocked count from native code
            sFilteredCount.set(jniGetFilteredCount())

            // Update notification
            val manager = getSystemService(NotificationManager::class.java)
            manager?.notify(NOTIFICATION_ID, buildNotification())

            // Schedule next update
            mHandler.postDelayed(this::updateStatistics, 5000)
        }
    }

    // Build notification
    private fun buildNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent, PendingIntent.FLAG_IMMUTABLE)

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.notification_active,
                sFilteredCount.get()))
            .setSmallIcon(R.drawable.ic_vpn_service)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    // Create notification channel
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW)

            channel.description = getString(R.string.notification_channel_description)

            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }
}