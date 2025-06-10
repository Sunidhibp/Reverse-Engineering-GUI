#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QTextEdit>
#include <QFileDialog>
#include <QFile>
#include <QByteArray>
#include <QMessageBox>
#include <QLabel>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QProcess>
#include <windows.h>
#include <winnt.h>
#include <QListWidget>
#include <QHeaderView>
#include <QGroupBox>
#include <QCheckBox>
#include <QProgressBar>
#include <QTimer>
#include <QTreeWidget>
#include <QLibrary>
#include <QDebug>
#include <cmath>
#include <QCryptographicHash>
#include <QRegularExpression>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QRegularExpression>


class ReverseEngineeringGUI : public QWidget {
    Q_OBJECT
public:
    ReverseEngineeringGUI(QWidget *parent = nullptr) : QWidget(parent) {
        setWindowTitle("Advanced Reverse Engineering GUI");
        resize(1400, 900);

        QVBoxLayout *mainLayout = new QVBoxLayout(this);
        QTabWidget *tabWidget = new QTabWidget(this);

        createHexViewerTab(tabWidget);
        createStringExtractionTab(tabWidget);
        createEntropyAnalysisTab(tabWidget);
        createBinarySignatureTab(tabWidget);
        createPEAnalysisTab(tabWidget);

        createHashCalculatorTab(tabWidget);
        createPatternSearchTab(tabWidget);

        createAntiDebuggingTab(tabWidget);

        mainLayout->addWidget(tabWidget);
    }

private:
    void createHexViewerTab(QTabWidget *tabWidget) {
        QWidget *hexViewTab = new QWidget();
        QVBoxLayout *hexLayout = new QVBoxLayout(hexViewTab);

        QHBoxLayout *controlLayout = new QHBoxLayout();
        QPushButton *loadButton = new QPushButton("Load Binary File", hexViewTab);
        QPushButton *exportButton = new QPushButton("Export Hex View", hexViewTab);

        hexViewer = new QTextEdit(hexViewTab);
        hexViewer->setReadOnly(true);

        controlLayout->addWidget(loadButton);
        controlLayout->addWidget(exportButton);

        hexLayout->addLayout(controlLayout);
        hexLayout->addWidget(hexViewer);

        connect(loadButton, &QPushButton::clicked, this, &ReverseEngineeringGUI::loadFile);
        connect(exportButton, &QPushButton::clicked, this, &ReverseEngineeringGUI::exportHexView);

        hexViewTab->setLayout(hexLayout);
        tabWidget->addTab(hexViewTab, "Hex Viewer");
    }

    void createStringExtractionTab(QTabWidget *tabWidget) {
        QWidget *stringExtractionTab = new QWidget();
        QVBoxLayout *stringLayout = new QVBoxLayout(stringExtractionTab);

        QHBoxLayout *controlLayout = new QHBoxLayout();
        QPushButton *extractButton = new QPushButton("Extract Strings", stringExtractionTab);
        QCheckBox *unicodeCheck = new QCheckBox("Include Unicode", stringExtractionTab);

        extractedStrings = new QTextEdit(stringExtractionTab);
        extractedStrings->setReadOnly(true);

        controlLayout->addWidget(extractButton);
        controlLayout->addWidget(unicodeCheck);

        stringLayout->addLayout(controlLayout);
        stringLayout->addWidget(new QLabel("Extracted Strings:"));
        stringLayout->addWidget(extractedStrings);

        connect(extractButton, &QPushButton::clicked, this, &ReverseEngineeringGUI::extractStrings);

        stringExtractionTab->setLayout(stringLayout);
        tabWidget->addTab(stringExtractionTab, "String Extraction");
    }

    void createEntropyAnalysisTab(QTabWidget *tabWidget) {
        QWidget *entropyAnalysisTab = new QWidget();
        QVBoxLayout *entropyLayout = new QVBoxLayout(entropyAnalysisTab);

        entropyResult = new QLabel("Entropy Analysis: Not Performed", entropyAnalysisTab);
        entropyHistogram = new QTableWidget(256, 2, entropyAnalysisTab);
        entropyHistogram->setHorizontalHeaderLabels({"Byte", "Frequency"});
        entropyHistogram->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

        entropyLayout->addWidget(entropyResult);
        entropyLayout->addWidget(entropyHistogram);

        entropyAnalysisTab->setLayout(entropyLayout);
        tabWidget->addTab(entropyAnalysisTab, "Entropy Analysis");
    }

    void createPEAnalysisTab(QTabWidget *tabWidget) {
        QWidget *peAnalysisTab = new QWidget();
        QVBoxLayout *peLayout = new QVBoxLayout(peAnalysisTab);

        peDetails = new QTextEdit(peAnalysisTab);
        peDetails->setReadOnly(true);

        peLayout->addWidget(new QLabel("PE Header Analysis:"));
        peLayout->addWidget(peDetails);

        peAnalysisTab->setLayout(peLayout);
        tabWidget->addTab(peAnalysisTab, "PE Analysis");
    }

    void createHashCalculatorTab(QTabWidget *tabWidget) {
        QWidget *hashTab = new QWidget();
        QVBoxLayout *hashLayout = new QVBoxLayout(hashTab);

        QPushButton *calculateHashButton = new QPushButton("Calculate Hashes", hashTab);
        hashResults = new QTextEdit(hashTab);
        hashResults->setReadOnly(true);

        hashLayout->addWidget(calculateHashButton);
        hashLayout->addWidget(hashResults);

        connect(calculateHashButton, &QPushButton::clicked, this, &ReverseEngineeringGUI::calculateFileHashes);

        hashTab->setLayout(hashLayout);
        tabWidget->addTab(hashTab, "Hash Calculator");
    }

    void createPatternSearchTab(QTabWidget *tabWidget) {
        QWidget *patternTab = new QWidget();
        QVBoxLayout *patternLayout = new QVBoxLayout(patternTab);

        QHBoxLayout *searchLayout = new QHBoxLayout();
        patternSearch = new QTextEdit(patternTab);
        QPushButton *searchButton = new QPushButton("Search Pattern", patternTab);

        patternResults = new QTextEdit(patternTab);
        patternResults->setReadOnly(true);

        searchLayout->addWidget(patternSearch);
        searchLayout->addWidget(searchButton);

        patternLayout->addLayout(searchLayout);
        patternLayout->addWidget(patternResults);

        connect(searchButton, &QPushButton::clicked, this, &ReverseEngineeringGUI::searchBinaryPattern);

        patternTab->setLayout(patternLayout);
        tabWidget->addTab(patternTab, "Pattern Search");
    }

    void createBinarySignatureTab(QTabWidget *tabWidget) {
        QWidget *signatureTab = new QWidget();
        QVBoxLayout *signatureLayout = new QVBoxLayout(signatureTab);

        signatureResults = new QTextEdit(signatureTab);
        signatureResults->setReadOnly(true);

        QPushButton *identifyButton = new QPushButton("Identify Binary", signatureTab);

        signatureLayout->addWidget(identifyButton);
        signatureLayout->addWidget(signatureResults);

        connect(identifyButton, &QPushButton::clicked, this, &ReverseEngineeringGUI::identifyBinarySignature);

        signatureTab->setLayout(signatureLayout);
        tabWidget->addTab(signatureTab, "Binary Signature");
    }

    void createAntiDebuggingTab(QTabWidget *tabWidget) {
        QWidget *antiDebuggingTab = new QWidget();
        QVBoxLayout *layout = new QVBoxLayout(antiDebuggingTab);

        QPushButton *checkDebuggerButton = new QPushButton("Check for Debugger", antiDebuggingTab);

        connect(checkDebuggerButton, &QPushButton::clicked, this, &ReverseEngineeringGUI::checkForDebugger);

        layout->addWidget(checkDebuggerButton);

        antiDebuggingTab->setLayout(layout);
        tabWidget->addTab(antiDebuggingTab, "Anti-Debugging Check");
    }

    void checkForDebugger() {
        if (IsDebuggerPresent()) {
            QMessageBox::critical(this, "Anti-Debugging Check", "Debugger Detected!");
        } else {
            QMessageBox::information(this, "Anti-Debugging Check", "No Debugger Detected.");
        }
    }

    void exportHexView() {
        if (binaryData.isEmpty()) {
            QMessageBox::warning(this, "Export Error", "No file loaded.");
            return;
        }

        QString fileName = QFileDialog::getSaveFileName(this, "Export Hex View", "", "Text Files (*.txt)");
        if (fileName.isEmpty()) return;

        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << hexViewer->toPlainText();
            file.close();
            QMessageBox::information(this, "Export", "Hex view exported successfully.");
        }
    }

#include <QRegularExpression> // Make sure this is at the top of your file

    void searchBinaryPattern() {
        if (binaryData.isEmpty()) {
            patternResults->setText("No file loaded. Please load a file first.");
            return;
        }

        QString pattern = patternSearch->toPlainText().trimmed();
        if (pattern.isEmpty()) {
            QMessageBox::warning(this, "Search Error", "Please enter a pattern.");
            return;
        }

        QByteArray patternBytes;

        // If pattern has characters not valid in hex, treat it as ASCII
        if (pattern.contains(QRegularExpression("[^0-9A-Fa-f\\s]"))) {
            patternBytes = pattern.toUtf8(); // raw ASCII pattern like "MZ"
        } else {
            patternBytes = QByteArray::fromHex(pattern.toLatin1()); // hex pattern like "4D5A"
        }

        if (patternBytes.isEmpty()) {
            patternResults->setText("Invalid pattern or empty after conversion.");
            return;
        }

        QList<qsizetype> matches;
        qsizetype dataSize = binaryData.size();
        qsizetype patternSize = patternBytes.size();

        for (qsizetype i = 0; i <= dataSize - patternSize; ++i) {
            if (binaryData.mid(i, patternSize) == patternBytes) {
                matches.append(i);
            }
        }

        QString resultText = "Pattern Search Results:\n";
        if (matches.isEmpty()) {
            resultText += "No matches found.";
        } else {
            resultText += QString("Found %1 matches at offsets:\n").arg(matches.size());
            for (qsizetype offset : matches) {
                resultText += QString("0x%1\n").arg(offset, 0, 16);
            }
        }

        patternResults->setText(resultText);
    }



    void identifyBinarySignature() {
        if (binaryData.isEmpty()) {
            signatureResults->setText("No file loaded. Please load a file first.");
            return;
        }

        QJsonObject signatures;
        signatures["MZ Executable"] = "4D5A";
        signatures["PDF Document"] = "25504446";
        signatures["ZIP Archive"] = "504B0304";
        signatures["PNG Image"] = "89504E47";

        QString detectedSignatures;
        for (auto it = signatures.begin(); it != signatures.end(); ++it) {
            QByteArray signatureBytes = QByteArray::fromHex(it.value().toString().toLatin1());
            if (binaryData.startsWith(signatureBytes)) {
                detectedSignatures += it.key() + "\n";
            }
        }

        if (detectedSignatures.isEmpty()) {
            signatureResults->setText("No known signatures detected.");
        } else {
            signatureResults->setText("Detected Signatures:\n" + detectedSignatures);
        }
    }

    void calculateFileHashes() {
        if (binaryData.isEmpty()) {
            hashResults->setText("No file loaded. Please load a file first.");
            return;
        }

        QByteArray md5Hash = QCryptographicHash::hash(binaryData, QCryptographicHash::Md5);
        QByteArray sha1Hash = QCryptographicHash::hash(binaryData, QCryptographicHash::Sha1);
        QByteArray sha256Hash = QCryptographicHash::hash(binaryData, QCryptographicHash::Sha256);

        QString hashText = "File Hashes:\n\n";
        hashText += "MD5: " + md5Hash.toHex() + "\n\n";
        hashText += "SHA-1: " + sha1Hash.toHex() + "\n\n";
        hashText += "SHA-256: " + sha256Hash.toHex();

        hashResults->setText(hashText);
    }

    void performEntropyAnalysis() {
        if (binaryData.isEmpty()) {
            entropyResult->setText("Entropy Analysis: No data loaded.");
            return;
        }

        double entropy = 0.0;
        int frequency[256] = {0};
        for (unsigned char byte : binaryData) {
            frequency[byte]++;
        }

        for (int i = 0; i < 256; ++i) {
            double probability = (double)frequency[i] / binaryData.size();
            entropyHistogram->setItem(i, 0, new QTableWidgetItem(QString::number(i)));
            entropyHistogram->setItem(i, 1, new QTableWidgetItem(QString::number(frequency[i])));

            if (probability > 0) {
                entropy -= probability * log2(probability);
            }
        }

        entropyResult->setText("Entropy: " + QString::number(entropy, 'f', 4));
    }

    void analyzePEHeader() {
        if (binaryData.size() < sizeof(IMAGE_DOS_HEADER)) {
            peDetails->setText("Invalid PE file.");
            return;
        }

        IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER*)binaryData.data();
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            peDetails->setText("Not a valid PE file.");
            return;
        }

        QString peInfo = "PE Header Analysis:\n";
        peInfo += "DOS Signature: Valid\n";
        peInfo += "File Size: " + QString::number(binaryData.size()) + " bytes\n";

        peDetails->setText(peInfo);
    }

    void extractStrings() {
        if (binaryData.isEmpty()) {
            extractedStrings->setText("No file loaded.");
            return;
        }

        QString result;
        QString currentString;

        for (int i = 0; i < binaryData.size(); ++i) {
            char byte = binaryData[i];

            if (byte >= 32 && byte <= 126) {
                currentString += byte;
            }
            else if (byte == 0 && i + 1 < binaryData.size() && binaryData[i + 1] >= 32 && binaryData[i + 1] <= 126) {
                currentString += binaryData[i + 1];
                ++i; // Skip next null byte
            }
            else {
                if (currentString.length() >= 4) {
                    result += currentString + "\n";
                }
                currentString.clear();
            }
        }

        if (currentString.length() >= 4) {
            result += currentString + "\n";
        }

        extractedStrings->setText(result.isEmpty() ? "No strings found." : result);
    }


    QString byteArrayToHexDump(const QByteArray &data) {
        QString hexDump;
        for (int i = 0; i < data.size(); i++) {
            if (i % 16 == 0) hexDump += "\n";
            hexDump += QString("%1 ").arg((unsigned char)data[i], 2, 16, QChar('0')).toUpper();
        }
        return hexDump;
    }

    void loadFile() {
        QString fileName = QFileDialog::getOpenFileName(this, "Open Binary File", "", "All Files (*)");
        if (fileName.isEmpty()) return;

        QFile file(fileName);
        if (!file.open(QIODevice::ReadOnly)) {
            QMessageBox::critical(this, "Error", "Failed to open file.");
            return;
        }

        binaryData = file.readAll();
        file.close();

        hexViewer->setText(byteArrayToHexDump(binaryData));
        performEntropyAnalysis();
        analyzePEHeader();
        extractStrings();
    }

private:
    QTextEdit *hexViewer;
    QTextEdit *extractedStrings;
    QLabel *entropyResult;
    QTableWidget *entropyHistogram;
    QTextEdit *peDetails;
    QTextEdit *hashResults;
    QTextEdit *patternSearch;
    QTextEdit *patternResults;
    QTextEdit *signatureResults;
    QByteArray binaryData;
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    ReverseEngineeringGUI window;
    window.show();
    return app.exec();
}
