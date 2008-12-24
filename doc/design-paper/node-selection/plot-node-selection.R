## Load in data files
t1 = read.table("opt_1e-6.pickle.dat", header=TRUE)
t2 = read.table("opt_1e-3.pickle.dat", header=TRUE)
t3 = read.table("opt_1e-1.pickle.dat", header=TRUE)
t4 = read.table("opt_0.75.pickle.dat", header=TRUE)
t5 = read.table("opt_0.5.pickle.dat", header=TRUE)
t6 = read.table("opt_0.25.pickle.dat", header=TRUE)
t7 = read.table("opt_0.1.pickle.dat", header=TRUE)
tt = read.table("opt_tor.pickle.dat", header=TRUE)

## Calculate selection probabilties that Tor uses
o = t1$bw/sum(t1$bw)

#plot(t1$bw, cumsum(t1$prob), col="red", type="l")
#lines(t1$bw, cumsum(t2$prob), col="pink")
#lines(t1$bw, cumsum(t3$prob), col="blue")
#lines(t1$bw, cumsum(t4$prob), col="orange")
#lines(t1$bw, cumsum(t5$prob), col="purple")
#lines(t1$bw, cumsum(tt$prob))

## Plot probabiltieis
pdf("optimum-selection-probabilities.pdf")
col <- rainbow(8)
 plot(t1$bw, t1$prob, col=col[1], type="b", ylim=c(0,0.035),xlab="Bandwidth (cells/s)",
      ylab="Selection probability", frame.plot=FALSE)
lines(t1$bw, t2$prob, col=col[2], type="b")
lines(t1$bw, t3$prob, col=col[3], type="b")
lines(t1$bw, t4$prob, col=col[4], type="b")
lines(t1$bw, t5$prob, col=col[5], type="b")

## These are too messy
##lines(t1$bw, t6$prob, col=col[6], type="b")
##lines(t1$bw, t7$prob, col=col[7], type="b")

lines(t1$bw, tt$prob,col=col[8], type="b")
lines(t1$bw, o, type="l", lwd=2)

## Annotate graph
title(main="Optimum node selection probability")
x <- rep(8254.383, 4)
y <- c(0.03453717, 0.02553347, 0.02219589, 0.02048830)
par(xpd=TRUE)
text(x,y,c("50%", "75%", "90%", ">99%"), adj=c(0,0.5))
dev.off()

## Plot probabilities relative to what Tor does
pdf("relative-selection-probabilities.pdf")
 plot(t1$bw, t1$prob-o, col=col[1], type="b", xlab="Bandwidth (cells/s)",
      ylab="Selection probability - Tor's selection probability", frame.plot=FALSE, ylim=c(-0.002,0.015))
lines(t1$bw, t2$prob-o, col=col[2], type="b")
lines(t1$bw, t3$prob-o, col=col[3], type="b")
lines(t1$bw, t4$prob-o, col=col[4], type="b")
lines(t1$bw, t5$prob-o, col=col[5], type="b")
lines(t1$bw, tt$prob-o,col=col[8], type="b")

lines(range(t1$bw), rep(0,2), lty=2)

title(main="Selection probabilility compared to Tor")
x <- rep(8111.669, 4)
y <- c(1.396915e-02, 4.962766e-03, 1.635106e-03, 7.446809e-06)
par(xpd=TRUE)
text(x,y,c("50%", "75%", "90%", ">99%"), adj=c(0,0.5))
dev.off()
