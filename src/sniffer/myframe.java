package sniffer;

import java.awt.BorderLayout;

import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.rmi.activation.ActivationInstantiator;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTree;
import javax.swing.event.TreeModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;

import jdk.internal.org.objectweb.asm.tree.analysis.Analyzer;
import sniffer.mysniffer;

public class myframe extends JFrame implements ActionListener{
	JFrame jf;
	JButton start,stop,filter,stole;//������ť
	JComboBox<String> jc1,jc2;//�����б�����ѡ�������͹��˹���
	String[] columnNames={"no.","time","source","destination","protocol","length"};
	Object[][] data=new Object[0][6];
	JTable jt;//������ʾץ���İ��ı��
	DefaultTableModel dt;
	
	DefaultMutableTreeNode root=new DefaultMutableTreeNode("������");
	DefaultTreeModel treeModel = new DefaultTreeModel(root);
	JTree tree=new JTree(treeModel);//ʹ����״���չʾ��ͷ�и��ֶε�����
	
	JScrollPane jsp,jsp1,jsp2;
	mysniffer snif;
	JTextArea jta;//������ʾ��������
	JLabel j[],count[];//������ʾͳ�ƽ��
	JLabel tt;
	public myframe(){
		count=new JLabel[5];
		j=new JLabel[5];
		for(int i=0;i<5;i++){
			count[i]=new JLabel();
			j[i]=new JLabel();
			count[i].setFont(new Font("����", Font.PLAIN, 20));
			j[i].setFont(new Font("����", Font.PLAIN, 15));
			count[i].setText("0");
		}
		j[0].setText("TCP");
		j[1].setText("UDP");
		j[2].setText("ICMP");
		j[3].setText("ARP");
		j[4].setText("HTTP");
		snif=new mysniffer();
		jf=new JFrame("sniffer");
		jf.setLayout(null);
		start=new JButton("��ʼ");
		stop=new JButton("ֹͣ");
		filter=new JButton("����");
		stole=new JButton("������̽");
		jc1=new JComboBox<String>();
		String str[]={"���˹���","TCP","UDP","ICMP","ARP","HTTP"};
		jc2=new JComboBox<String>(str);
		jt=new JTable();
		dt=new DefaultTableModel(data, columnNames);
		jt.setModel(dt);
		jt.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		jsp=new JScrollPane(jt);
		jsp1=new JScrollPane(tree);
		jta=new JTextArea();
		jsp2=new JScrollPane(jta);
		jf.setSize(1000, 700);
		//������������뵽������
		jf.add(jc1);
		jf.add(start);
		jf.add(stop);
		jf.add(filter);
		jf.add(stole);
		jf.add(jc2);
		jf.add(jsp);
		jf.add(jsp1);
		jf.add(jsp2);
		for(int i=0;i<5;i++){
			jf.add(count[i]);
			jf.add(j[i]);
		}
		//���ø�������Ĵ�Сλ��
		jta.setBounds(300, 300, 500, 300);
		jsp2.setBounds(300, 300, 500, 300);
		tree.setBounds(25, 300, 250, 300);
		jsp1.setBounds(25, 300, 250, 300);
		jsp.setBounds(25, 80, 940, 200);
		jc1.setBounds(5, 5, 400, 20);
		int off=80;
		for(int i=0;i<5;i++){
			j[i].setBounds(830,190+off,40,80);
			count[i].setBounds(880, 190+off, 80, 80);
			off+=80;
		}
		jc2.setBounds(5, 35, 400, 20);
		start.setBounds(500, 10, 80,35);
		stop.setBounds(600,10,80,35);
		filter.setBounds(700,10,80,35);
		stole.setBounds(800,10,150,35);
		//���������������
		jta.setLineWrap(false);
		jc1.addItem("ѡ������");
		setCombobox(snif.getNetworkCard(), jc1);
		jt.addMouseListener(new MouseAdapter() {//�Ա��󶨵���¼�
			public void mouseClicked(MouseEvent e){
				if(e.getClickCount()==1){
					int index=((JTable)e.getSource()).rowAtPoint(e.getPoint());
					snif.analyze(index,tree);//�԰�ͷ���з���
					snif.printData(index,jta);//����������������ı�����
				}
			}
		});
		//������ť�󶨵���¼�
		start.addActionListener(this);	
		stop.addActionListener(this);
		filter.addActionListener(this);
		stole.addActionListener(this);
		jf.setVisible(true);
	}
	private void setCombobox(String buf[],JComboBox<String> jc){
		for(int i=0;i<buf.length;i++){
			jc.insertItemAt(buf[i], i+1);
		}
	}
	public void actionPerformed(ActionEvent e){
		if(e.getSource()==start){
			snif.setRunning(true);//�����߳����б�־
			if(jc1.getSelectedIndex()==0){//��ȡ�������
				JOptionPane.showMessageDialog(null, "��ѡ������", "alert", JOptionPane.ERROR_MESSAGE); 
				return;
			}
			snif.setJTableModel(dt, jt);//��JTable�ؼ�����ȥ����ÿץ��һ����ʱ������ӵ�JTable��ȥ��ʾ
			snif.initial(dt, jt,count);//�����ʼ��Ҫ��֮ǰ�Ľ������յ�
			if(snif.work(jc1.getSelectedIndex())<0){//����mysniffer�е�work��������ץ��
				JOptionPane.showMessageDialog(null, "���豸ʧ��", "alert", JOptionPane.ERROR_MESSAGE); 
				return;
			}
		}else if(e.getSource()==stop){
			snif.setRunning(false);//�����߳�ֹͣ�ı�־
			snif.updateCount(count);//�԰��ĸ�����ͳ��
		}else if(e.getSource()==filter){
			snif.filter((String)jc2.getSelectedItem(),dt,jt);//��ץ���İ����й���
		}else if(e.getSource()==stole){
			snif.getMessage();//�����ݰ����������еĴ�д��ĸת��Сд��ĸ
			snif.stole(dt, jt);//�����ݰ��к���pwd����password�ֶεİ���ȡ����
		}
	}
}
