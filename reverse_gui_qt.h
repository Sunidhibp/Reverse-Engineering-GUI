#ifndef REVERSE_GUI_QT_H
#define REVERSE_GUI_QT_H

#include <QWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QFileDialog>
#include <QFile>
#include <QMessageBox>

class ReverseEngineeringGUI : public QWidget {
    Q_OBJECT  // Required for Qt signals/slots

public:
    ReverseEngineeringGUI(QWidget *parent = nullptr);

private slots:
    void loadFile();

private:
    QTextEdit *hexViewer;
    QString byteArrayToHexDump(const QByteArray &data);
};

#endif // REVERSE_GUI_QT_H
