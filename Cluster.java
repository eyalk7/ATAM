import java.util.Scanner;

class Cluster {
	static int[] resizeArray(int[] oldArr) {
		int oldSize = oldArr.length;
		int[] newArr = new int[2*oldSize];
		for (int i=0; i<oldSize; i++) {
			newArr[i] = oldArr[i];
		}
		return newArr;
	}
	

	static void sortArray(int[] array) {
		int i , swapped = 1;
		while (swapped > 0) {
			swapped = 0;
			for (i=1; i<array.length; i++) {	
				if (array[i-1] > array[i]) {
					int temp = array[i-1];
					array[i-1] = array[i];
					array[i] = temp;	
					swapped = 1;
				}
			}
		}
	}

	public static int[] collectClusters(int[] sequence) {
		
		sortArray(sequence);
		int tempClusterCounter = 1;
		int[] tempCluster = new int[sequence.length];
		tempCluster[0] = sequence[0];
		int clustersCounter = 0;
		int[] clusters = new int[sequence.length];
		int index = 1;
		while (index < sequence.length) {
			if (sequence[index] > sequence[index-1]+1) {
				clusters[clustersCounter] = tempCluster[(tempClusterCounter-1)/2];
				tempCluster[0] = sequence[index];
				tempClusterCounter = 1;
				clustersCounter++;
			}
			else {
				tempCluster[tempClusterCounter] = sequence[index];
				tempClusterCounter++;
			}
			index++;	
		}
		clusters[clustersCounter] = tempCluster[(tempClusterCounter-1)/2];
		int[] finalClusters = new int[clustersCounter+1];
		for (int i=0; i<finalClusters.length; i++) {
			finalClusters[i] = clusters[i];
		}
		sortArray(finalClusters);
		return finalClusters;
	}

	public static void main(String[] args) {
		int arraySize = 100;
		int[] numbers = new int[arraySize];
		Scanner inputNums = new Scanner(System.in);
		int val = inputNums.nextInt();		
		int counter = 0;
		while (val>=0) {	
			numbers[counter] = val;
			counter++;
			if (counter == arraySize) {
				numbers = resizeArray(numbers);
				arraySize *= 2;
			}
			val = inputNums.nextInt();
		}
		if (counter == 0) {
			return;
		}
		int[] sequence = new int[counter];
		for (int i=0; i<counter; i++) {
			sequence[i] = numbers[i];
		}
		int[] result = Cluster.collectClusters(sequence);
		for (int i=0; i<result.length; i++) {
			System.out.print(result[i] + "\n");
		}
	}
}
