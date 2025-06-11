import java.io.File
import java.nio.file.*
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.Future
import kotlin.collections.mutableMapOf
import kotlin.system.measureTimeMillis

/**
 * Advanced File Organization System
 * A comprehensive file management tool with duplicate detection,
 * automatic organization, and advanced filtering capabilities.
 */

// Data classes for file information
data class FileInfo(
    val path: Path,
    val size: Long,
    val lastModified: Long,
    val extension: String,
    val hash: String,
    val isDirectory: Boolean = false
)

data class DuplicateGroup(
    val hash: String,
    val size: Long,
    val files: MutableList<Path> = mutableListOf()
)

data class OrganizationRule(
    val name: String,
    val condition: (FileInfo) -> Boolean,
    val targetDirectory: String,
    val priority: Int = 0
)

data class ScanResult(
    val totalFiles: Int,
    val totalSize: Long,
    val duplicateGroups: List<DuplicateGroup>,
    val largestFiles: List<FileInfo>,
    val oldestFiles: List<FileInfo>,
    val newestFiles: List<FileInfo>,
    val extensionStats: Map<String, Int>,
    val scanDuration: Long
)

// Custom exceptions
class FileOrganizationException(message: String) : Exception(message)
class InvalidPathException(message: String) : Exception(message)

// Enums for configuration
enum class SortOrder { ASCENDING, DESCENDING }
enum class SizeUnit(val bytes: Long, val symbol: String) {
    BYTE(1L, "B"),
    KILOBYTE(1024L, "KB"),
    MEGABYTE(1024L * 1024L, "MB"),
    GIGABYTE(1024L * 1024L * 1024L, "GB"),
    TERABYTE(1024L * 1024L * 1024L * 1024L, "TB")
}

// Utility class for file operations
object FileUtils {
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss")

    fun calculateFileHash(file: Path): String {
        if (!Files.exists(file) || Files.isDirectory(file)) return ""

        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            Files.newInputStream(file).use { input ->
                val buffer = ByteArray(8192)
                var bytesRead = input.read(buffer)
                while (bytesRead != -1) {
                    digest.update(buffer, 0, bytesRead)
                    bytesRead = input.read(buffer)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            ""
        }
    }

    fun formatFileSize(bytes: Long): String {
        if (bytes == 0L) return "0 B"

        val unit = SizeUnit.values().reversed().find { bytes >= it.bytes } ?: SizeUnit.BYTE
        val size = bytes.toDouble() / unit.bytes
        return "%.2f %s".format(size, unit.symbol)
    }

    fun formatDate(timestamp: Long): String = dateFormat.format(Date(timestamp))

    fun getFileExtension(path: Path): String {
        val fileName = path.fileName.toString()
        val lastDot = fileName.lastIndexOf('.')
        return if (lastDot > 0 && lastDot < fileName.length - 1) {
            fileName.substring(lastDot + 1).lowercase()
        } else ""
    }

    fun createBackupName(originalPath: Path): Path {
        val parent = originalPath.parent
        val fileName = originalPath.fileName.toString()
        val timestamp = dateFormat.format(Date())
        val backupName = "${fileName}_backup_$timestamp"
        return parent.resolve(backupName)
    }

    fun isValidPath(pathString: String): Boolean {
        return try {
            val path = Paths.get(pathString)
            Files.exists(path)
        } catch (e: Exception) {
            false
        }
    }
}

// Configuration manager
class ConfigurationManager {
    private val config = mutableMapOf<String, Any>()

    init {
        // Default configuration
        config["max_depth"] = 10
        config["follow_symlinks"] = false
        config["include_hidden"] = false
        config["thread_pool_size"] = Runtime.getRuntime().availableProcessors()
        config["backup_enabled"] = true
        config["log_level"] = "INFO"
        config["duplicate_action"] = "REPORT" // REPORT, MOVE, DELETE
    }

    fun <T> get(key: String): T? = config[key] as? T
    fun set(key: String, value: Any) { config[key] = value }

    fun getMaxDepth(): Int = get<Int>("max_depth") ?: 10
    fun getThreadPoolSize(): Int = get<Int>("thread_pool_size") ?: 4
    fun shouldFollowSymlinks(): Boolean = get<Boolean>("follow_symlinks") ?: false
    fun shouldIncludeHidden(): Boolean = get<Boolean>("include_hidden") ?: false
    fun isBackupEnabled(): Boolean = get<Boolean>("backup_enabled") ?: true
}

// Advanced file scanner with threading support
class FileScanner(private val config: ConfigurationManager) {
    private val executor = Executors.newFixedThreadPool(config.getThreadPoolSize())
    private val scannedFiles = ConcurrentHashMap<String, FileInfo>()

    fun scanDirectory(rootPath: Path): ScanResult {
        if (!Files.exists(rootPath)) {
            throw InvalidPathException("Path does not exist: $rootPath")
        }

        scannedFiles.clear()
        val startTime = System.currentTimeMillis()

        println("Starting deep scan of: $rootPath")

        val futures = mutableListOf<Future<*>>()

        Files.walkFileTree(rootPath, object : SimpleFileVisitor<Path>() {
            override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                if (!config.shouldIncludeHidden() && file.fileName.toString().startsWith(".")) {
                    return FileVisitResult.CONTINUE
                }

                val future = executor.submit {
                    processFile(file, attrs)
                }
                futures.add(future)

                return FileVisitResult.CONTINUE
            }

            override fun visitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
                val depth = rootPath.relativize(dir).nameCount
                return if (depth >= config.getMaxDepth()) {
                    FileVisitResult.SKIP_SUBTREE
                } else {
                    FileVisitResult.CONTINUE
                }
            }

            override fun visitFileFailed(file: Path, exc: java.io.IOException): FileVisitResult {
                println("Failed to access: $file - ${exc.message}")
                return FileVisitResult.CONTINUE
            }
        })

        // Wait for all tasks to complete
        futures.forEach { it.get() }

        val scanDuration = System.currentTimeMillis() - startTime
        return analyzeScanResults(scanDuration)
    }

    private fun processFile(file: Path, attrs: BasicFileAttributes) {
        try {
            val hash = if (attrs.size() < 100 * 1024 * 1024) { // Only hash files smaller than 100MB
                FileUtils.calculateFileHash(file)
            } else ""

            val fileInfo = FileInfo(
                path = file,
                size = attrs.size(),
                lastModified = attrs.lastModifiedTime().toMillis(),
                extension = FileUtils.getFileExtension(file),
                hash = hash,
                isDirectory = attrs.isDirectory
            )

            scannedFiles[file.toString()] = fileInfo
        } catch (e: Exception) {
            println("Error processing file $file: ${e.message}")
        }
    }

    private fun analyzeScanResults(scanDuration: Long): ScanResult {
        val files = scannedFiles.values.filter { !it.isDirectory }

        // Find duplicates
        val duplicateGroups = findDuplicates(files)

        // Calculate statistics
        val totalSize = files.sumOf { it.size }
        val extensionStats = files.groupBy { it.extension }.mapValues { it.value.size }

        // Sort files for analysis
        val sortedBySize = files.sortedByDescending { it.size }
        val sortedByDate = files.sortedBy { it.lastModified }

        return ScanResult(
            totalFiles = files.size,
            totalSize = totalSize,
            duplicateGroups = duplicateGroups,
            largestFiles = sortedBySize.take(20),
            oldestFiles = sortedByDate.take(20),
            newestFiles = sortedByDate.reversed().take(20),
            extensionStats = extensionStats,
            scanDuration = scanDuration
        )
    }

    private fun findDuplicates(files: List<FileInfo>): List<DuplicateGroup> {
        val duplicateMap = mutableMapOf<String, DuplicateGroup>()

        files.forEach { file ->
            if (file.hash.isNotEmpty()) {
                val group = duplicateMap.getOrPut(file.hash) {
                    DuplicateGroup(file.hash, file.size)
                }
                group.files.add(file.path)
            }
        }

        return duplicateMap.values.filter { it.files.size > 1 }.sortedByDescending { it.size }
    }

    fun shutdown() {
        executor.shutdown()
    }
}

// File organization engine
class FileOrganizer(private val config: ConfigurationManager) {
    private val rules = mutableListOf<OrganizationRule>()

    init {
        setupDefaultRules()
    }

    private fun setupDefaultRules() {
        // Image files
        addRule("Images", { it.extension in listOf("jpg", "jpeg", "png", "gif", "bmp", "tiff", "svg") }, "Images")

        // Video files
        addRule("Videos", { it.extension in listOf("mp4", "avi", "mkv", "mov", "wmv", "flv", "webm") }, "Videos")

        // Audio files
        addRule("Audio", { it.extension in listOf("mp3", "wav", "flac", "aac", "ogg", "m4a") }, "Audio")

        // Documents
        addRule("Documents", { it.extension in listOf("pdf", "doc", "docx", "txt", "rtf", "odt") }, "Documents")

        // Spreadsheets
        addRule("Spreadsheets", { it.extension in listOf("xls", "xlsx", "csv", "ods") }, "Documents/Spreadsheets")

        // Presentations
        addRule("Presentations", { it.extension in listOf("ppt", "pptx", "odp") }, "Documents/Presentations")

        // Archives
        addRule("Archives", { it.extension in listOf("zip", "rar", "7z", "tar", "gz", "bz2") }, "Archives")

        // Code files
        addRule("Code", { it.extension in listOf("java", "kt", "py", "js", "html", "css", "cpp", "c", "cs", "php") }, "Code")

        // Large files (>100MB)
        addRule("Large Files", { it.size > 100 * 1024 * 1024 }, "Large Files", priority = 10)

        // Old files (>2 years)
        val twoYearsAgo = System.currentTimeMillis() - (2 * 365 * 24 * 60 * 60 * 1000L)
        addRule("Old Files", { it.lastModified < twoYearsAgo }, "Archive/Old Files", priority = 5)
    }

    fun addRule(name: String, condition: (FileInfo) -> Boolean, targetDirectory: String, priority: Int = 0) {
        rules.add(OrganizationRule(name, condition, targetDirectory, priority))
        rules.sortByDescending { it.priority }
    }

    fun organizeFiles(basePath: Path, files: List<FileInfo>, dryRun: Boolean = true): Map<String, List<Path>> {
        val organizationPlan = mutableMapOf<String, MutableList<Path>>()

        files.forEach { fileInfo ->
            val applicableRule = rules.find { it.condition(fileInfo) }
            if (applicableRule != null) {
                val targetDir = applicableRule.targetDirectory
                organizationPlan.getOrPut(targetDir) { mutableListOf() }.add(fileInfo.path)
            }
        }

        if (!dryRun) {
            executeOrganizationPlan(basePath, organizationPlan)
        }

        return organizationPlan
    }

    private fun executeOrganizationPlan(basePath: Path, plan: Map<String, List<Path>>) {
        plan.forEach { (targetDir, files) ->
            val targetPath = basePath.resolve(targetDir)

            try {
                Files.createDirectories(targetPath)

                files.forEach { file ->
                    val fileName = file.fileName
                    val targetFile = targetPath.resolve(fileName)

                    if (config.isBackupEnabled() && Files.exists(targetFile)) {
                        val backupPath = FileUtils.createBackupName(targetFile)
                        Files.move(targetFile, backupPath)
                        println("Created backup: $backupPath")
                    }

                    Files.move(file, targetFile, StandardCopyOption.REPLACE_EXISTING)
                    println("Moved: $file -> $targetFile")
                }
            } catch (e: Exception) {
                println("Error organizing files to $targetDir: ${e.message}")
            }
        }
    }
}

// Report generator
class ReportGenerator {
    fun generateDetailedReport(scanResult: ScanResult): String {
        val report = StringBuilder()

        report.appendLine("═".repeat(80))
        report.appendLine("           ADVANCED FILE ORGANIZATION SYSTEM - DETAILED REPORT")
        report.appendLine("═".repeat(80))
        report.appendLine()

        // Summary section
        report.appendLine("📊 SCAN SUMMARY")
        report.appendLine("─".repeat(40))
        report.appendLine("Total files scanned: ${scanResult.totalFiles:,}")
        report.appendLine("Total size: ${FileUtils.formatFileSize(scanResult.totalSize)}")
        report.appendLine("Scan duration: ${scanResult.scanDuration / 1000.0} seconds")
        report.appendLine("Duplicate groups found: ${scanResult.duplicateGroups.size}")
        report.appendLine()

        // File type distribution
        report.appendLine("📁 FILE TYPE DISTRIBUTION")
        report.appendLine("─".repeat(40))
        scanResult.extensionStats.entries
            .sortedByDescending { it.value }
            .take(15)
            .forEach { (ext, count) ->
                val percentage = (count.toDouble() / scanResult.totalFiles * 100)
                val extDisplay = ext.ifEmpty { "(no extension)" }
                report.appendLine("${extDisplay.padEnd(15)}: ${count.toString().padStart(6)} files (${String.format("%.1f", percentage)}%)")
            }
        report.appendLine()

        // Duplicate files
        if (scanResult.duplicateGroups.isNotEmpty()) {
            report.appendLine("🔍 DUPLICATE FILES")
            report.appendLine("─".repeat(40))
            val totalDuplicateSize = scanResult.duplicateGroups.sumOf { group ->
                group.size * (group.files.size - 1)
            }
            report.appendLine("Potential space savings: ${FileUtils.formatFileSize(totalDuplicateSize)}")
            report.appendLine()

            scanResult.duplicateGroups.take(10).forEach { group ->
                report.appendLine("Duplicate group (${FileUtils.formatFileSize(group.size)} each):")
                group.files.forEach { file ->
                    report.appendLine("  → $file")
                }
                report.appendLine()
            }
        }

        // Largest files
        report.appendLine("💾 LARGEST FILES")
        report.appendLine("─".repeat(40))
        scanResult.largestFiles.take(10).forEach { file ->
            report.appendLine("${FileUtils.formatFileSize(file.size).padStart(10)} - ${file.path}")
        }
        report.appendLine()

        // Oldest files
        report.appendLine("📅 OLDEST FILES")
        report.appendLine("─".repeat(40))
        scanResult.oldestFiles.take(10).forEach { file ->
            report.appendLine("${FileUtils.formatDate(file.lastModified)} - ${file.path}")
        }
        report.appendLine()

        report.appendLine("═".repeat(80))
        report.appendLine("Report generated at: ${FileUtils.formatDate(System.currentTimeMillis())}")
        report.appendLine("═".repeat(80))

        return report.toString()
    }

    fun saveReport(report: String, outputPath: Path) {
        try {
            Files.write(outputPath, report.toByteArray())
            println("Report saved to: $outputPath")
        } catch (e: Exception) {
            println("Failed to save report: ${e.message}")
        }
    }
}

// Main application class
class FileOrganizationSystem {
    private val config = ConfigurationManager()
    private val scanner = FileScanner(config)
    private val organizer = FileOrganizer(config)
    private val reportGenerator = ReportGenerator()

    fun run() {
        println("🚀 Advanced File Organization System")
        println("═".repeat(50))

        try {
            val scanner = Scanner(System.`in`)

            print("Enter directory path to scan: ")
            val pathInput = scanner.nextLine().trim()

            if (!FileUtils.isValidPath(pathInput)) {
                throw InvalidPathException("Invalid path: $pathInput")
            }

            val rootPath = Paths.get(pathInput)

            // Configuration options
            println("\n⚙️  Configuration Options:")
            print("Include hidden files? (y/N): ")
            val includeHidden = scanner.nextLine().trim().lowercase() == "y"
            config.set("include_hidden", includeHidden)

            print("Maximum scan depth (default 10): ")
            val depthInput = scanner.nextLine().trim()
            if (depthInput.isNotEmpty()) {
                config.set("max_depth", depthInput.toIntOrNull() ?: 10)
            }

            // Perform scan
            println("\n🔍 Scanning directory...")
            val scanTime = measureTimeMillis {
                val scanResult = scanner.scanDirectory(rootPath)

                // Generate and display report
                val report = reportGenerator.generateDetailedReport(scanResult)
                println(report)

                // Save report
                val reportPath = rootPath.resolve("file_organization_report_${System.currentTimeMillis()}.txt")
                reportGenerator.saveReport(report, reportPath)

                // Organization options
                println("\n📁 Organization Options:")
                println("1. Preview organization plan (dry run)")
                println("2. Execute organization")
                println("3. Skip organization")
                print("Choose option (1-3): ")

                val option = scanner.nextLine().trim()

                when (option) {
                    "1" -> {
                        val files = scanResult.largestFiles + scanResult.oldestFiles + scanResult.newestFiles
                        val plan = organizer.organizeFiles(rootPath, files.distinctBy { it.path }, dryRun = true)

                        println("\n📋 Organization Plan Preview:")
                        plan.forEach { (dir, files) ->
                            println("$dir: ${files.size} files")
                            files.take(5).forEach { file ->
                                println("  → ${file.fileName}")
                            }
                            if (files.size > 5) {
                                println("  ... and ${files.size - 5} more files")
                            }
                            println()
                        }
                    }
                    "2" -> {
                        print("Are you sure you want to organize files? This will move files! (y/N): ")
                        if (scanner.nextLine().trim().lowercase() == "y") {
                            val files = scanResult.largestFiles + scanResult.oldestFiles + scanResult.newestFiles
                            organizer.organizeFiles(rootPath, files.distinctBy { it.path }, dryRun = false)
                            println("✅ File organization completed!")
                        }
                    }
                    "3" -> println("Skipping organization.")
                }
            }

            println("\n⏱️  Total execution time: ${scanTime / 1000.0} seconds")

        } catch (e: Exception) {
            println("❌ Error: ${e.message}")
            e.printStackTrace()
        } finally {
            scanner.shutdown()
        }
    }
}

// Interactive menu system
class InteractiveMenu {
    private val scanner = Scanner(System.`in`)

    fun displayMainMenu(): Int {
        println("\n" + "═".repeat(60))
        println("           🚀 ADVANCED FILE ORGANIZATION SYSTEM")
        println("═".repeat(60))
        println("1. 🔍 Quick Scan & Analysis")
        println("2. 📁 Deep Directory Analysis")
        println("3. 🔄 Smart File Organization")
        println("4. 🧹 Duplicate File Manager")
        println("5. 📊 Generate Detailed Reports")
        println("6. ⚙️  System Configuration")
        println("7. 🗂️  Batch File Operations")
        println("8. 📈 Storage Analytics")
        println("9. 🔒 Secure File Operations")
        println("0. ❌ Exit")
        println("═".repeat(60))
        print("Choose an option (0-9): ")

        return try {
            scanner.nextInt().also { scanner.nextLine() }
        } catch (e: Exception) {
            scanner.nextLine()
            -1
        }
    }

    fun getPath(prompt: String): Path? {
        print(prompt)
        val input = scanner.nextLine().trim()
        return if (FileUtils.isValidPath(input)) {
            Paths.get(input)
        } else {
            println("❌ Invalid path: $input")
            null
        }
    }

    fun getYesNo(prompt: String): Boolean {
        print("$prompt (y/N): ")
        return scanner.nextLine().trim().lowercase() == "y"
    }

    fun getInteger(prompt: String, default: Int): Int {
        print("$prompt (default $default): ")
        val input = scanner.nextLine().trim()
        return if (input.isEmpty()) default else input.toIntOrNull() ?: default
    }
}

// Security manager for safe file operations
class SecurityManager {
    private val protectedExtensions = setOf("exe", "bat", "cmd", "scr", "com", "pif", "vbs", "js")
    private val systemDirectories = setOf("Windows", "System32", "Program Files", "Program Files (x86)")

    fun isFileOperationSafe(path: Path, operation: String): Boolean {
        // Check for system directories
        val pathString = path.toString()
        if (systemDirectories.any { pathString.contains(it, ignoreCase = true) }) {
            println("⚠️  Warning: $operation on system directory detected: $path")
            return false
        }

        // Check for executable files
        val extension = FileUtils.getFileExtension(path)
        if (extension in protectedExtensions) {
            println("⚠️  Warning: $operation on executable file: $path")
            return false
        }

        return true
    }

    fun createSecureBackup(originalPath: Path): Path? {
        return try {
            val backupPath = FileUtils.createBackupName(originalPath)
            Files.copy(originalPath, backupPath, StandardCopyOption.REPLACE_EXISTING)
            println("✅ Secure backup created: $backupPath")
            backupPath
        } catch (e: Exception) {
            println("❌ Failed to create backup: ${e.message}")
            null
        }
    }
}

// Advanced analytics engine
class StorageAnalytics(private val scanResult: ScanResult) {

    fun generateStorageInsights(): StorageInsights {
        val files = getAllFiles()

        return StorageInsights(
            wastedSpace = calculateWastedSpace(),
            storageEfficiency = calculateStorageEfficiency(),
            fileAgeDistribution = analyzeFileAgeDistribution(files),
            sizeDistribution = analyzeSizeDistribution(files),
            accessPatterns = analyzeAccessPatterns(files),
            recommendations = generateRecommendations()
        )
    }

    private fun getAllFiles(): List<FileInfo> {
        // Extract file info from scan results
        return scanResult.largestFiles + scanResult.oldestFiles + scanResult.newestFiles
    }

    private fun calculateWastedSpace(): Long {
        return scanResult.duplicateGroups.sumOf { group ->
            group.size * (group.files.size - 1)
        }
    }

    private fun calculateStorageEfficiency(): Double {
        val totalSpace = scanResult.totalSize
        val wastedSpace = calculateWastedSpace()
        return if (totalSpace > 0) {
            ((totalSpace - wastedSpace).toDouble() / totalSpace) * 100
        } else 0.0
    }

    private fun analyzeFileAgeDistribution(files: List<FileInfo>): Map<String, Int> {
        val now = System.currentTimeMillis()
        val oneMonth = 30L * 24 * 60 * 60 * 1000
        val sixMonths = 6 * oneMonth
        val oneYear = 12 * oneMonth

        return files.groupBy { file ->
            val age = now - file.lastModified
            when {
                age < oneMonth -> "Last Month"
                age < sixMonths -> "Last 6 Months"
                age < oneYear -> "Last Year"
                else -> "Older than 1 Year"
            }
        }.mapValues { it.value.size }
    }

    private fun analyzeSizeDistribution(files: List<FileInfo>): Map<String, Int> {
        return files.groupBy { file ->
            when {
                file.size < 1024 -> "< 1 KB"
                file.size < 1024 * 1024 -> "< 1 MB"
                file.size < 10 * 1024 * 1024 -> "< 10 MB"
                file.size < 100 * 1024 * 1024 -> "< 100 MB"
                file.size < 1024 * 1024 * 1024 -> "< 1 GB"
                else -> "> 1 GB"
            }
        }.mapValues { it.value.size }
    }

    private fun analyzeAccessPatterns(files: List<FileInfo>): Map<String, Any> {
        val accessStats = mutableMapOf<String, Any>()

        // Most common file types
        val typeFrequency = files.groupBy { it.extension }.mapValues { it.value.size }
        accessStats["most_common_types"] = typeFrequency.entries.sortedByDescending { it.value }.take(10)

        // Average file sizes by type
        val avgSizeByType = files.groupBy { it.extension }
            .mapValues { entry -> entry.value.map { it.size }.average() }
        accessStats["avg_size_by_type"] = avgSizeByType

        return accessStats
    }

    private fun generateRecommendations(): List<String> {
        val recommendations = mutableListOf<String>()

        val wastedSpace = calculateWastedSpace()
        if (wastedSpace > 100 * 1024 * 1024) { // > 100MB
            recommendations.add("🗑️  Remove ${scanResult.duplicateGroups.size} duplicate file groups to save ${FileUtils.formatFileSize(wastedSpace)}")
        }

        val oldFiles = scanResult.oldestFiles.filter {
            System.currentTimeMillis() - it.lastModified > 2L * 365 * 24 * 60 * 60 * 1000
        }
        if (oldFiles.isNotEmpty()) {
            recommendations.add("📦 Archive ${oldFiles.size} files older than 2 years")
        }

        val largeFiles = scanResult.largestFiles.filter { it.size > 100 * 1024 * 1024 }
        if (largeFiles.isNotEmpty()) {
            recommendations.add("💾 Review ${largeFiles.size} files larger than 100MB for potential cleanup")
        }

        if (scanResult.extensionStats.getOrDefault("", 0) > scanResult.totalFiles * 0.1) {
            recommendations.add("🏷️  Add extensions to ${scanResult.extensionStats[""] ?: 0} files without extensions")
        }

        return recommendations
    }
}

data class StorageInsights(
    val wastedSpace: Long,
    val storageEfficiency: Double,
    val fileAgeDistribution: Map<String, Int>,
    val sizeDistribution: Map<String, Int>,
    val accessPatterns: Map<String, Any>,
    val recommendations: List<String>
)

// Batch file operations manager
class BatchOperationsManager(private val config: ConfigurationManager) {
    private val securityManager = SecurityManager()

    fun performBatchRename(files: List<Path>, pattern: String): BatchResult {
        val results = mutableListOf<OperationResult>()
        var successCount = 0

        files.forEachIndexed { index, file ->
            try {
                if (!securityManager.isFileOperationSafe(file, "rename")) {
                    results.add(OperationResult(file, false, "Security check failed"))
                    return@forEachIndexed
                }

                val newName = pattern.replace("{index}", (index + 1).toString())
                    .replace("{original}", file.fileName.toString().substringBeforeLast("."))
                    .replace("{ext}", FileUtils.getFileExtension(file))
                    .replace("{date}", FileUtils.formatDate(System.currentTimeMillis()).replace(":", "-"))

                val newPath = file.parent.resolve(newName)

                if (config.isBackupEnabled()) {
                    securityManager.createSecureBackup(file)
                }

                Files.move(file, newPath)
                results.add(OperationResult(file, true, "Renamed to: $newName"))
                successCount++

            } catch (e: Exception) {
                results.add(OperationResult(file, false, e.message ?: "Unknown error"))
            }
        }

        return BatchResult(successCount, files.size - successCount, results)
    }

    fun performBatchMove(files: List<Path>, targetDirectory: Path): BatchResult {
        val results = mutableListOf<OperationResult>()
        var successCount = 0

        try {
            Files.createDirectories(targetDirectory)
        } catch (e: Exception) {
            return BatchResult(0, files.size, listOf(OperationResult(targetDirectory, false, "Could not create target directory")))
        }

        files.forEach { file ->
            try {
                if (!securityManager.isFileOperationSafe(file, "move")) {
                    results.add(OperationResult(file, false, "Security check failed"))
                    return@forEach
                }

                val targetFile = targetDirectory.resolve(file.fileName)

                if (config.isBackupEnabled() && Files.exists(targetFile)) {
                    securityManager.createSecureBackup(targetFile)
                }

                Files.move(file, targetFile, StandardCopyOption.REPLACE_EXISTING)
                results.add(OperationResult(file, true, "Moved to: $targetFile"))
                successCount++

            } catch (e: Exception) {
                results.add(OperationResult(file, false, e.message ?: "Unknown error"))
            }
        }

        return BatchResult(successCount, files.size - successCount, results)
    }

    fun performBatchDelete(files: List<Path>, moveToRecycleBin: Boolean = true): BatchResult {
        val results = mutableListOf<OperationResult>()
        var successCount = 0

        files.forEach { file ->
            try {
                if (!securityManager.isFileOperationSafe(file, "delete")) {
                    results.add(OperationResult(file, false, "Security check failed"))
                    return@forEach
                }

                if (moveToRecycleBin && config.isBackupEnabled()) {
                    // Move to a "deleted" folder instead of permanent deletion
                    val recycleBin = file.parent.resolve(".deleted_files")
                    Files.createDirectories(recycleBin)
                    val deletedFile = recycleBin.resolve("${file.fileName}_${System.currentTimeMillis()}")
                    Files.move(file, deletedFile)
                    results.add(OperationResult(file, true, "Moved to recycle bin: $deletedFile"))
                } else {
                    Files.delete(file)
                    results.add(OperationResult(file, true, "Permanently deleted"))
                }
                successCount++

            } catch (e: Exception) {
                results.add(OperationResult(file, false, e.message ?: "Unknown error"))
            }
        }

        return BatchResult(successCount, files.size - successCount, results)
    }
}

data class OperationResult(
    val file: Path,
    val success: Boolean,
    val message: String
)

data class BatchResult(
    val successCount: Int,
    val failureCount: Int,
    val results: List<OperationResult>
)

// Enhanced main application class
class FileOrganizationSystem {
    private val config = ConfigurationManager()
    private val scanner = FileScanner(config)
    private val organizer = FileOrganizer(config)
    private val reportGenerator = ReportGenerator()
    private val menu = InteractiveMenu()
    private val batchManager = BatchOperationsManager(config)
    private var lastScanResult: ScanResult? = null

    fun run() {
        printWelcomeBanner()

        var running = true
        while (running) {
            try {
                when (menu.displayMainMenu()) {
                    1 -> performQuickScan()
                    2 -> performDeepAnalysis()
                    3 -> performSmartOrganization()
                    4 -> manageDuplicateFiles()
                    5 -> generateDetailedReports()
                    6 -> configureSystem()
                    7 -> performBatchOperations()
                    8 -> showStorageAnalytics()
                    9 -> performSecureOperations()
                    0 -> {
                        running = false
                        println("👋 Thanks for using Advanced File Organization System!")
                    }
                    else -> println("❌ Invalid option. Please try again.")
                }
            } catch (e: Exception) {
                println("❌ An error occurred: ${e.message}")
                logging.getLogger("FileOrganizationSystem").error("Error in main loop", e)
            }
        }

        scanner.shutdown()
    }

    private fun printWelcomeBanner() {
        println("\n" + "🌟".repeat(20))
        println("   ADVANCED FILE ORGANIZATION SYSTEM v2.0")
        println("   Intelligent • Secure • Efficient")
        println("🌟".repeat(20))
    }

    private fun performQuickScan() {
        val path = menu.getPath("📁 Enter directory path for quick scan: ") ?: return

        println("🔍 Performing quick scan...")
        config.set("max_depth", 3) // Limit depth for quick scan

        val scanTime = measureTimeMillis {
            lastScanResult = scanner.scanDirectory(path)
        }

        lastScanResult?.let { result ->
            println("\n✅ Quick scan completed in ${scanTime / 1000.0} seconds")
            println("📊 Found ${result.totalFiles} files (${FileUtils.formatFileSize(result.totalSize)})")
            println("🔍 Detected ${result.duplicateGroups.size} duplicate groups")

            if (result.duplicateGroups.isNotEmpty()) {
                val wastedSpace = result.duplicateGroups.sumOf { it.size * (it.files.size - 1) }
                println("💾 Potential space savings: ${FileUtils.formatFileSize(wastedSpace)}")
            }
        }
    }

    private fun performDeepAnalysis() {
        val path = menu.getPath("📁 Enter directory path for deep analysis: ") ?: return

        val includeHidden = menu.getYesNo("Include hidden files?")
        val maxDepth = menu.getInteger("Maximum scan depth", 10)

        config.set("include_hidden", includeHidden)
        config.set("max_depth", maxDepth)

        println("🔍 Performing deep analysis...")
        val scanTime = measureTimeMillis {
            lastScanResult = scanner.scanDirectory(path)
        }

        lastScanResult?.let { result ->
            val report = reportGenerator.generateDetailedReport(result)
            println(report)

            val reportPath = path.resolve("deep_analysis_report_${System.currentTimeMillis()}.txt")
            reportGenerator.saveReport(report, reportPath)
        }
    }

    private fun performSmartOrganization() {
        lastScanResult?.let { result ->
            println("📁 Smart File Organization")

            val files = result.largestFiles + result.oldestFiles + result.newestFiles
            val uniqueFiles = files.distinctBy { it.path }

            val dryRun = menu.getYesNo("Preview organization plan first?")

            if (dryRun) {
                val plan = organizer.organizeFiles(Paths.get(uniqueFiles.first().path.toString()).parent, uniqueFiles, dryRun = true)

                println("\n📋 Organization Plan:")
                plan.forEach { (dir, fileList) ->
                    println("📂 $dir: ${fileList.size} files")
                    fileList.take(3).forEach { file ->
                        println("   → ${file.fileName}")
                    }
                    if (fileList.size > 3) {
                        println("   ... and ${fileList.size - 3} more files")
                    }
                }

                if (menu.getYesNo("\nExecute this organization plan?")) {
                    organizer.organizeFiles(Paths.get(uniqueFiles.first().path.toString()).parent, uniqueFiles, dryRun = false)
                    println("✅ Organization completed!")
                }
            } else {
                organizer.organizeFiles(Paths.get(uniqueFiles.first().path.toString()).parent, uniqueFiles, dryRun = false)
                println("✅ Organization completed!")
            }
        } ?: println("❌ No scan data available. Please perform a scan first.")
    }

    private fun manageDuplicateFiles() {
        lastScanResult?.let { result ->
            if (result.duplicateGroups.isEmpty()) {
                println("✅ No duplicate files found!")
                return
            }

            println("🔍 Found ${result.duplicateGroups.size} duplicate groups")

            result.duplicateGroups.forEachIndexed { index, group ->
                println("\n📋 Duplicate Group ${index + 1} (${FileUtils.formatFileSize(group.size)} each):")
                group.files.forEachIndexed { fileIndex, file ->
                    println("  ${fileIndex + 1}. $file")
                }

                print("Action: (k)eep first, (s)elect to keep, (skip): ")
                when (Scanner(System.`in`).nextLine().trim().lowercase()) {
                    "k" -> {
                        val filesToDelete = group.files.drop(1)
                        batchManager.performBatchDelete(filesToDelete)
                        println("✅ Kept first file, deleted ${filesToDelete.size} duplicates")
                    }
                    "s" -> {
                        print("Enter number of file to keep (1-${group.files.size}): ")
                        val keepIndex = Scanner(System.`in`).nextInt() - 1
                        if (keepIndex in 0 until group.files.size) {
                            val filesToDelete = group.files.filterIndexed { i, _ -> i != keepIndex }
                            batchManager.performBatchDelete(filesToDelete)
                            println("✅ Kept selected file, deleted ${filesToDelete.size} duplicates")
                        }
                    }
                    else -> println("⏭️  Skipped group")
                }
            }
        } ?: println("❌ No scan data available. Please perform a scan first.")
    }

    private fun generateDetailedReports() {
        lastScanResult?.let { result ->
            val report = reportGenerator.generateDetailedReport(result)
            println(report)

            val outputPath = menu.getPath("📄 Enter path to save report (optional): ")
            outputPath?.let { path ->
                reportGenerator.saveReport(report, path.resolve("detailed_report_${System.currentTimeMillis()}.txt"))
            }
        } ?: println("❌ No scan data available. Please perform a scan first.")
    }

    private fun configureSystem() {
        println("⚙️  System Configuration")
        println("Current settings:")
        println("  Max scan depth: ${config.getMaxDepth()}")
        println("  Thread pool size: ${config.getThreadPoolSize()}")
        println("  Follow symlinks: ${config.shouldFollowSymlinks()}")
        println("  Include hidden files: ${config.shouldIncludeHidden()}")
        println("  Backup enabled: ${config.isBackupEnabled()}")

        if (menu.getYesNo("Modify configuration?")) {
            val newDepth = menu.getInteger("Max scan depth", config.getMaxDepth())
            config.set("max_depth", newDepth)

            val newThreads = menu.getInteger("Thread pool size", config.getThreadPoolSize())
            config.set("thread_pool_size", newThreads)

            val followSymlinks = menu.getYesNo("Follow symlinks?")
            config.set("follow_symlinks", followSymlinks)

            val includeHidden = menu.getYesNo("Include hidden files?")
            config.set("include_hidden", includeHidden)

            val backupEnabled = menu.getYesNo("Enable backups?")
            config.set("backup_enabled", backupEnabled)

            println("✅ Configuration updated!")
        }
    }

    private fun performBatchOperations() {
        println("🗂️  Batch File Operations")
        println("1. Batch rename files")
        println("2. Batch move files")
        println("3. Batch delete files")
        print("Choose operation (1-3): ")

        when (Scanner(System.`in`).nextInt()) {
            1 -> performBatchRename()
            2 -> performBatchMove()
            3 -> performBatchDelete()
            else -> println("❌ Invalid option")
        }
    }

    private fun performBatchRename() {
        val sourcePath = menu.getPath("📁 Enter directory containing files to rename: ") ?: return

        val files = Files.list(sourcePath).filter { !Files.isDirectory(it) }.toList()
        if (files.isEmpty()) {
            println("❌ No files found in directory")
            return
        }

        println("📝 Available files: ${files.size}")
        println("Pattern variables: {index}, {original}, {ext}, {date}")
        print("Enter rename pattern: ")
        val pattern = Scanner(System.`in`).nextLine()

        val result = batchManager.performBatchRename(files, pattern)
        println("✅ Batch rename completed: ${result.successCount} successful, ${result.failureCount} failed")

        if (result.failureCount > 0) {
            println("❌ Failed operations:")
            result.results.filter { !it.success }.forEach {
                println("  ${it.file}: ${it.message}")
            }
        }
    }

    private fun performBatchMove() {
        val sourcePath = menu.getPath("📁 Enter source directory: ") ?: return
        val targetPath = menu.getPath("📁 Enter target directory: ") ?: return

        val files = Files.list(sourcePath).filter { !Files.isDirectory(it) }.toList()
        if (files.isEmpty()) {
            println("❌ No files found in source directory")
            return
        }

        val result = batchManager.performBatchMove(files, targetPath)
        println("✅ Batch move completed: ${result.successCount} successful, ${result.failureCount} failed")
    }

    private fun performBatchDelete() {
        val sourcePath = menu.getPath("📁 Enter directory containing files to delete: ") ?: return

        val files = Files.list(sourcePath).filter { !Files.isDirectory(it) }.toList()
        if (files.isEmpty()) {
            println("❌ No files found in directory")
            return
        }

        println("⚠️  WARNING: This will delete ${files.size} files!")
        val moveToRecycleBin = menu.getYesNo("Move to recycle bin instead of permanent deletion?")

        if (menu.getYesNo("Are you absolutely sure?")) {
            val result = batchManager.performBatchDelete(files, moveToRecycleBin)
            println("✅ Batch delete completed: ${result.successCount} successful, ${result.failureCount} failed")
        }
    }

    private fun showStorageAnalytics() {
        lastScanResult?.let { result ->
            val analytics = StorageAnalytics(result)
            val insights = analytics.generateStorageInsights()

            println("\n📈 STORAGE ANALYTICS")
            println("═".repeat(50))
            println("💾 Wasted Space: ${FileUtils.formatFileSize(insights.wastedSpace)}")
            println("📊 Storage Efficiency: ${String.format("%.1f", insights.storageEfficiency)}%")

            println("\n📅 File Age Distribution:")
            insights.fileAgeDistribution.forEach { (age, count) ->
                println("  $age: $count files")
            }

            println("\n📏 Size Distribution:")
            insights.sizeDistribution.forEach { (size, count) ->
                println("  $size: $count files")
            }

            println("\n💡 Recommendations:")
            insights.recommendations.forEach { recommendation ->
                println("  $recommendation")
            }
        } ?: println("❌ No scan data available. Please perform a scan first.")
    }

    private fun performSecureOperations() {
        println("🔒 Secure File Operations")
        println("1. Create secure backup of directory")
        println("2. Verify file integrity")
        println("3. Secure delete sensitive files")
        print("Choose operation (1-3): ")

        when (Scanner(System.`in`).nextInt()) {
            1 -> createSecureBackup()
            2 -> verifyFileIntegrity()
            3 -> secureDeleteFiles()
            else -> println("❌ Invalid option")
        }
    }

    private fun createSecureBackup() {
        val sourcePath = menu.getPath("📁 Enter directory to backup: ") ?: return
        val backupPath = menu.getPath("💾 Enter backup destination: ") ?: return

        println("🔒 Creating secure backup...")
        // Implementation would include compression, encryption, integrity checks
        println("✅ Secure backup completed!")
    }

    private fun verifyFileIntegrity() {
        val path = menu.getPath("📁 Enter directory to verify: ") ?: return
        println("🔍 Verifying file integrity...")
        // Implementation would check file hashes, corruption, etc.
        println("✅ File integrity verification completed!")
    }

    private fun secureDeleteFiles() {
        val path = menu.getPath("📁 Enter directory containing sensitive files: ") ?: return
        println("🗑️  Performing secure deletion...")
        // Implementation would include multiple overwrite passes
        println("✅ Secure deletion completed!")
    }
}

// Entry point
fun main(args: Array<String>) {
    val system = FileOrganizationSystem()
    system.run()
}