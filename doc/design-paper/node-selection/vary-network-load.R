## The waiting time for a node (assuming no overloaded nodes)
## x: 1/bandwidth
## q: selection probability
## L: network load
wait <- function(x,q,L) {
  a <- q*L*x*x
  b <- 2*(1-q*x*L)
  return (x + a/b)
}

## The weighted wait time
wwait <- function(x,q,L) {
  return (q*wait(x,q,L))
}

## Average latency, returning NA for infinite
netLatency <- function(x, q, L) {
  if (any(x*q*L <0 | x*q*L >1)) {
    return (NA)
  } else {
    return (sum(wwait(x, q, L)))
  }
}

## Load in data files
t1 <- read.table("opt_1e-6.pickle.dat", header=TRUE)
t2 <- read.table("opt_1e-3.pickle.dat", header=TRUE)
t3 <- read.table("opt_1e-1.pickle.dat", header=TRUE)
t4 <- read.table("opt_0.75.pickle.dat", header=TRUE)
t5 <- read.table("opt_0.5.pickle.dat", header=TRUE)
t6 <- read.table("opt_0.25.pickle.dat", header=TRUE)
t7 <- read.table("opt_0.1.pickle.dat", header=TRUE)
tt <- read.table("opt_tor.pickle.dat", header=TRUE)

## Node bandwidth and reciprocal
bw <- t1$bw
x <- 1/bw

## Calculate network capcity
capacity <- sum(bw)

## Calculate selection probabilties that Tor uses
torProb <- bw/sum(bw)

## Load values to try
varyLoad <- seq(0.01,0.93,0.01)
latencyTor <- c()
latency3 <- c()
latency4 <- c()
latency5 <- c()
for (L in varyLoad) {
  latencyTor <- append(latencyTor,
                       netLatency(x, torProb, capacity*L))
  latency3   <- append(latency3,
                       netLatency(x, t3$prob, capacity*L))
  latency4   <- append(latency4,
                       netLatency(x, t4$prob, capacity*L))
  latency5   <- append(latency5,
                       netLatency(x, t5$prob, capacity*L))
}

## Output graph
pdf("vary-network-load.pdf")

## Set up axes
yFac <- 1000
xFac <- 100

ylim <- range(na.omit(c(latencyTor, latency3, latency4, latency5)))
ylim <- c(0,0.015) * yFac
xlim <- c(0,1) * xFac
plot(NA, NA,
     xlim=xlim, ylim=ylim,
     frame.plot=FALSE,
     xlab = "Network load (%)",
     ylab = "Average queuing delay (ms)",
     main = "Latency for varying network loads")

## Plot data
col <- rainbow(8)
lines(varyLoad*xFac, latency3*yFac, col=col[3])
lines(varyLoad*xFac, latency4*yFac, col=col[4])
lines(varyLoad*xFac, latency5*yFac, col=col[5])
lines(varyLoad*xFac, latencyTor*yFac)

## Plot points at which selection probabilities are optimal
par(xpd=TRUE)
points(c(0.9, 0.75, 0.5, 1)*xFac, rep(par("usr")[3], 4),
       col=c(col[3:5], "black"), pch=20,
       cex=2)

## Close output device
dev.off()
