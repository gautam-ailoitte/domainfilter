package com.example.domainfilter.util

import android.content.Context
import android.content.SharedPreferences
import android.preference.PreferenceManager
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class FilterManager(context: Context) {
    companion object {
        private const val TAG = "FilterManager"

        // Default filter lists
        private val DEFAULT_FILTER_LISTS = arrayOf(
            "advertising", // Common advertising domains
            "tracking",    // Tracking domains
            "malware"      // Known malware domains
        )
    }

    // JNI methods for domain filtering
    private external fun jniInitFilter()
    private external fun jniAddDomain(domain: String)
    private external fun jniLoadFilterFile(filePath: String)
    private external fun jniCheckDomain(domain: String): Boolean

    private val mContext: Context = context.applicationContext
    private val mPrefs: SharedPreferences = PreferenceManager.getDefaultSharedPreferences(mContext)
    private val mExecutor: ExecutorService = Executors.newSingleThreadExecutor()

    init {
        // Initialize native filter
        jniInitFilter()
    }

    // Load default filter lists
    fun loadDefaultFilters() {
        mExecutor.execute {
            for (list in DEFAULT_FILTER_LISTS) {
                if (mPrefs.getBoolean("filter_$list", true)) {
                    loadFilterAsset("$list.txt")
                }
            }
        }
    }

    // Add a single domain to the filter
    fun addDomain(domain: String) {
        mExecutor.execute { jniAddDomain(domain) }
    }

    // Add multiple domains to the filter
    fun addDomains(domains: List<String>) {
        mExecutor.execute {
            domains.forEach { domain ->
                jniAddDomain(domain)
            }
        }
    }

    // Load filter from assets
    private fun loadFilterAsset(assetName: String) {
        try {
            val inputStream = mContext.assets.open("filters/$assetName")
            val outputFile = File(mContext.filesDir, assetName)

            // Copy the asset to internal storage
            inputStream.use { input ->
                FileOutputStream(outputFile).use { output ->
                    input.copyTo(output)
                }
            }

            // Load the filter file
            jniLoadFilterFile(outputFile.absolutePath)

            Log.i(TAG, "Loaded filter asset: $assetName")
        } catch (e: IOException) {
            Log.e(TAG, "Error loading filter asset: $assetName", e)
        }
    }

    // Load filter from a URL
    fun loadFilterFromUrl(url: String, fileName: String) {
        mExecutor.execute {
            try {
                val connection = URL(url).openConnection() as HttpURLConnection
                connection.requestMethod = "GET"
                connection.connectTimeout = 15000
                connection.readTimeout = 15000
                connection.connect()

                val responseCode = connection.responseCode
                if (responseCode == HttpURLConnection.HTTP_OK) {
                    val outputFile = File(mContext.filesDir, fileName)
                    connection.inputStream.use { input ->
                        FileOutputStream(outputFile).use { output ->
                            input.copyTo(output)
                        }
                    }

                    // Load the filter file
                    jniLoadFilterFile(outputFile.absolutePath)

                    Log.i(TAG, "Loaded filter from URL: $url")
                } else {
                    Log.e(TAG, "Error loading filter from URL: $url, response code: $responseCode")
                }
            } catch (e: IOException) {
                Log.e(TAG, "Error loading filter from URL: $url", e)
            }
        }
    }

    // Check if a domain is blocked
    fun isDomainBlocked(domain: String): Boolean {
        return jniCheckDomain(domain)
    }

    // Parse hosts file from input stream
    @Throws(IOException::class)
    fun parseHostsFile(inputStream: InputStream): List<String> {
        val domains = mutableListOf<String>()
        BufferedReader(InputStreamReader(inputStream)).use { reader ->
            reader.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .forEach { line ->
                    val parts = line.split("\\s+".toRegex())
                    if (parts.size >= 2) {
                        // First part is the IP address, second part is the domain
                        domains.add(parts[1])
                    }
                }
        }

        return domains
    }
}